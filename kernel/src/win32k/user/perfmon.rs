//! Performance Monitor
//!
//! Implements the Performance Monitor following Windows Server 2003.
//! Provides real-time system performance monitoring and logging.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - perfmon.msc - Performance console
//! - System Monitor ActiveX control
//! - Performance Logs and Alerts

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use crate::ke::spinlock::SpinLock;
use super::UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum counters
const MAX_COUNTERS: usize = 64;

/// Maximum data points per counter
const MAX_DATA_POINTS: usize = 100;

/// Maximum name length
const MAX_NAME: usize = 64;

/// Maximum log entries
const MAX_LOGS: usize = 16;

// ============================================================================
// Counter Category
// ============================================================================

/// Performance counter category
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CounterCategory {
    /// Processor
    #[default]
    Processor = 0,
    /// Memory
    Memory = 1,
    /// Physical Disk
    PhysicalDisk = 2,
    /// Network Interface
    Network = 3,
    /// System
    System = 4,
    /// Process
    Process = 5,
    /// Thread
    Thread = 6,
    /// Objects
    Objects = 7,
    /// Cache
    Cache = 8,
    /// Paging File
    PagingFile = 9,
}

impl CounterCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            CounterCategory::Processor => "Processor",
            CounterCategory::Memory => "Memory",
            CounterCategory::PhysicalDisk => "PhysicalDisk",
            CounterCategory::Network => "Network Interface",
            CounterCategory::System => "System",
            CounterCategory::Process => "Process",
            CounterCategory::Thread => "Thread",
            CounterCategory::Objects => "Objects",
            CounterCategory::Cache => "Cache",
            CounterCategory::PagingFile => "Paging File",
        }
    }
}

// ============================================================================
// Display Style
// ============================================================================

/// Graph display style
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DisplayStyle {
    /// Line graph
    #[default]
    Line = 0,
    /// Histogram bar
    Histogram = 1,
    /// Report (text)
    Report = 2,
}

impl DisplayStyle {
    pub fn as_str(&self) -> &'static str {
        match self {
            DisplayStyle::Line => "Line",
            DisplayStyle::Histogram => "Histogram Bar",
            DisplayStyle::Report => "Report",
        }
    }
}

// ============================================================================
// Counter Scale
// ============================================================================

/// Counter scale factor
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CounterScale {
    /// 0.0000001
    Scale7 = 0,
    /// 0.000001
    Scale6 = 1,
    /// 0.00001
    Scale5 = 2,
    /// 0.0001
    Scale4 = 3,
    /// 0.001
    Scale3 = 4,
    /// 0.01
    Scale2 = 5,
    /// 0.1
    Scale1 = 6,
    /// 1.0 (default)
    #[default]
    Scale0 = 7,
    /// 10.0
    ScaleP1 = 8,
    /// 100.0
    ScaleP2 = 9,
    /// 1000.0
    ScaleP3 = 10,
}

// ============================================================================
// Line Style
// ============================================================================

/// Counter line style
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LineStyle {
    /// Solid line
    #[default]
    Solid = 0,
    /// Dashed line
    Dash = 1,
    /// Dotted line
    Dot = 2,
    /// Dash-dot line
    DashDot = 3,
}

// ============================================================================
// Counter Entry
// ============================================================================

/// Performance counter entry
#[derive(Debug, Clone, Copy)]
pub struct CounterEntry {
    /// Counter ID
    pub counter_id: u32,
    /// Category
    pub category: CounterCategory,
    /// Counter name
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: usize,
    /// Instance name (e.g., "_Total", "0", "C:")
    pub instance: [u8; 32],
    /// Instance length
    pub instance_len: usize,
    /// Current value
    pub current_value: u64,
    /// Average value
    pub average_value: u64,
    /// Minimum value
    pub min_value: u64,
    /// Maximum value
    pub max_value: u64,
    /// Data points (ring buffer)
    pub data_points: [u64; MAX_DATA_POINTS],
    /// Current data point index
    pub data_index: usize,
    /// Data point count
    pub data_count: usize,
    /// Display color (RGB)
    pub color: u32,
    /// Line width
    pub line_width: u8,
    /// Line style
    pub line_style: LineStyle,
    /// Scale factor
    pub scale: CounterScale,
    /// Is visible
    pub visible: bool,
}

impl CounterEntry {
    pub const fn new() -> Self {
        Self {
            counter_id: 0,
            category: CounterCategory::Processor,
            name: [0u8; MAX_NAME],
            name_len: 0,
            instance: [0u8; 32],
            instance_len: 0,
            current_value: 0,
            average_value: 0,
            min_value: u64::MAX,
            max_value: 0,
            data_points: [0u64; MAX_DATA_POINTS],
            data_index: 0,
            data_count: 0,
            color: 0x00FF00, // Green
            line_width: 1,
            line_style: LineStyle::Solid,
            scale: CounterScale::Scale0,
            visible: true,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    pub fn set_instance(&mut self, instance: &[u8]) {
        let len = instance.len().min(32);
        self.instance[..len].copy_from_slice(&instance[..len]);
        self.instance_len = len;
    }

    pub fn add_data_point(&mut self, value: u64) {
        self.data_points[self.data_index] = value;
        self.data_index = (self.data_index + 1) % MAX_DATA_POINTS;
        if self.data_count < MAX_DATA_POINTS {
            self.data_count += 1;
        }

        self.current_value = value;
        if value < self.min_value {
            self.min_value = value;
        }
        if value > self.max_value {
            self.max_value = value;
        }

        // Calculate average
        let mut sum: u64 = 0;
        for i in 0..self.data_count {
            sum = sum.saturating_add(self.data_points[i]);
        }
        if self.data_count > 0 {
            self.average_value = sum / self.data_count as u64;
        }
    }
}

impl Default for CounterEntry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Log Entry
// ============================================================================

/// Performance log configuration
#[derive(Debug, Clone, Copy)]
pub struct LogConfig {
    /// Log ID
    pub log_id: u32,
    /// Log name
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: usize,
    /// Log file path
    pub path: [u8; 128],
    /// Path length
    pub path_len: usize,
    /// Sample interval (seconds)
    pub interval: u32,
    /// Is running
    pub running: bool,
    /// Log format (binary, CSV, etc.)
    pub format: LogFormat,
    /// Counter IDs to log
    pub counter_ids: [u32; 16],
    /// Counter count
    pub counter_count: usize,
}

impl LogConfig {
    pub const fn new() -> Self {
        Self {
            log_id: 0,
            name: [0u8; MAX_NAME],
            name_len: 0,
            path: [0u8; 128],
            path_len: 0,
            interval: 15,
            running: false,
            format: LogFormat::Binary,
            counter_ids: [0; 16],
            counter_count: 0,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    pub fn set_path(&mut self, path: &[u8]) {
        let len = path.len().min(128);
        self.path[..len].copy_from_slice(&path[..len]);
        self.path_len = len;
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Log format
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogFormat {
    /// Binary log file
    #[default]
    Binary = 0,
    /// Comma-separated values
    Csv = 1,
    /// Tab-separated values
    Tsv = 2,
    /// SQL database
    Sql = 3,
}

// ============================================================================
// Graph Settings
// ============================================================================

/// Graph display settings
#[derive(Debug, Clone, Copy)]
pub struct GraphSettings {
    /// Display style
    pub style: DisplayStyle,
    /// Vertical scale maximum
    pub vertical_max: u64,
    /// Vertical scale minimum
    pub vertical_min: u64,
    /// Auto-scale
    pub auto_scale: bool,
    /// Show grid
    pub show_grid: bool,
    /// Grid color
    pub grid_color: u32,
    /// Background color
    pub bg_color: u32,
    /// Update interval (seconds)
    pub update_interval: u32,
    /// Duration (seconds to display)
    pub duration: u32,
    /// Show legend
    pub show_legend: bool,
    /// Show value bar
    pub show_value_bar: bool,
    /// Show toolbar
    pub show_toolbar: bool,
}

impl GraphSettings {
    pub const fn new() -> Self {
        Self {
            style: DisplayStyle::Line,
            vertical_max: 100,
            vertical_min: 0,
            auto_scale: true,
            show_grid: true,
            grid_color: 0x404040,
            bg_color: 0x000000,
            update_interval: 1,
            duration: 100,
            show_legend: true,
            show_value_bar: true,
            show_toolbar: true,
        }
    }
}

impl Default for GraphSettings {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Performance Monitor State
// ============================================================================

/// Performance Monitor state
struct PerfmonState {
    /// Active counters
    counters: [CounterEntry; MAX_COUNTERS],
    /// Counter count
    counter_count: usize,
    /// Next counter ID
    next_counter_id: u32,
    /// Log configurations
    logs: [LogConfig; MAX_LOGS],
    /// Log count
    log_count: usize,
    /// Next log ID
    next_log_id: u32,
    /// Graph settings
    graph: GraphSettings,
    /// Is monitoring active
    monitoring: bool,
    /// Selected counter ID
    selected_counter: u32,
}

impl PerfmonState {
    pub const fn new() -> Self {
        Self {
            counters: [const { CounterEntry::new() }; MAX_COUNTERS],
            counter_count: 0,
            next_counter_id: 1,
            logs: [const { LogConfig::new() }; MAX_LOGS],
            log_count: 0,
            next_log_id: 1,
            graph: GraphSettings::new(),
            monitoring: false,
            selected_counter: 0,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static PERFMON_INITIALIZED: AtomicBool = AtomicBool::new(false);
static PERFMON_STATE: SpinLock<PerfmonState> = SpinLock::new(PerfmonState::new());

// Statistics
static SAMPLE_COUNT: AtomicU64 = AtomicU64::new(0);
static COUNTER_ADDS: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize Performance Monitor
pub fn init() {
    if PERFMON_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = PERFMON_STATE.lock();

    // Add default counters
    add_default_counters(&mut state);

    crate::serial_println!("[WIN32K] Performance Monitor initialized");
}

/// Add default counters
fn add_default_counters(state: &mut PerfmonState) {
    let counters: [(CounterCategory, &[u8], &[u8], u32); 8] = [
        (CounterCategory::Processor, b"% Processor Time", b"_Total", 0x00FF00),
        (CounterCategory::Memory, b"Available MBytes", b"", 0x0000FF),
        (CounterCategory::Memory, b"Pages/sec", b"", 0xFFFF00),
        (CounterCategory::PhysicalDisk, b"% Disk Time", b"_Total", 0xFF0000),
        (CounterCategory::PhysicalDisk, b"Disk Bytes/sec", b"_Total", 0xFF00FF),
        (CounterCategory::Network, b"Bytes Total/sec", b"Local Area Connection", 0x00FFFF),
        (CounterCategory::System, b"Processor Queue Length", b"", 0xFFA500),
        (CounterCategory::PagingFile, b"% Usage", b"_Total", 0x800080),
    ];

    for (category, name, instance, color) in counters.iter() {
        if state.counter_count >= MAX_COUNTERS {
            break;
        }
        let mut counter = CounterEntry::new();
        counter.counter_id = state.next_counter_id;
        state.next_counter_id += 1;
        counter.category = *category;
        counter.set_name(name);
        counter.set_instance(instance);
        counter.color = *color;

        // Initialize with sample data
        for j in 0..10 {
            counter.add_data_point((j * 10) as u64 % 100);
        }

        let idx = state.counter_count;
        state.counters[idx] = counter;
        state.counter_count += 1;
    }
}

// ============================================================================
// Counter Management
// ============================================================================

/// Add a counter
pub fn add_counter(category: CounterCategory, name: &[u8], instance: &[u8]) -> Option<u32> {
    let mut state = PERFMON_STATE.lock();
    if state.counter_count >= MAX_COUNTERS {
        return None;
    }

    let counter_id = state.next_counter_id;
    state.next_counter_id += 1;

    let mut counter = CounterEntry::new();
    counter.counter_id = counter_id;
    counter.category = category;
    counter.set_name(name);
    counter.set_instance(instance);
    counter.color = 0x00FF00; // Default green

    let idx = state.counter_count;
    state.counters[idx] = counter;
    state.counter_count += 1;

    COUNTER_ADDS.fetch_add(1, Ordering::Relaxed);
    Some(counter_id)
}

/// Remove a counter
pub fn remove_counter(counter_id: u32) -> bool {
    let mut state = PERFMON_STATE.lock();

    let mut found_index = None;
    for i in 0..state.counter_count {
        if state.counters[i].counter_id == counter_id {
            found_index = Some(i);
            break;
        }
    }

    if let Some(index) = found_index {
        // Shift remaining counters
        for i in index..state.counter_count - 1 {
            state.counters[i] = state.counters[i + 1];
        }
        state.counter_count -= 1;
        true
    } else {
        false
    }
}

/// Get counter count
pub fn get_counter_count() -> usize {
    PERFMON_STATE.lock().counter_count
}

/// Get counter by index
pub fn get_counter(index: usize) -> Option<CounterEntry> {
    let state = PERFMON_STATE.lock();
    if index < state.counter_count {
        Some(state.counters[index])
    } else {
        None
    }
}

/// Get counter by ID
pub fn get_counter_by_id(counter_id: u32) -> Option<CounterEntry> {
    let state = PERFMON_STATE.lock();
    for i in 0..state.counter_count {
        if state.counters[i].counter_id == counter_id {
            return Some(state.counters[i]);
        }
    }
    None
}

/// Update counter value
pub fn update_counter(counter_id: u32, value: u64) -> bool {
    let mut state = PERFMON_STATE.lock();
    for i in 0..state.counter_count {
        if state.counters[i].counter_id == counter_id {
            state.counters[i].add_data_point(value);
            SAMPLE_COUNT.fetch_add(1, Ordering::Relaxed);
            return true;
        }
    }
    false
}

/// Set counter color
pub fn set_counter_color(counter_id: u32, color: u32) -> bool {
    let mut state = PERFMON_STATE.lock();
    for i in 0..state.counter_count {
        if state.counters[i].counter_id == counter_id {
            state.counters[i].color = color;
            return true;
        }
    }
    false
}

/// Set counter visibility
pub fn set_counter_visible(counter_id: u32, visible: bool) -> bool {
    let mut state = PERFMON_STATE.lock();
    for i in 0..state.counter_count {
        if state.counters[i].counter_id == counter_id {
            state.counters[i].visible = visible;
            return true;
        }
    }
    false
}

/// Select a counter
pub fn select_counter(counter_id: u32) {
    PERFMON_STATE.lock().selected_counter = counter_id;
}

/// Get selected counter
pub fn get_selected_counter() -> u32 {
    PERFMON_STATE.lock().selected_counter
}

// ============================================================================
// Graph Settings
// ============================================================================

/// Get graph settings
pub fn get_graph_settings() -> GraphSettings {
    PERFMON_STATE.lock().graph
}

/// Set display style
pub fn set_display_style(style: DisplayStyle) {
    PERFMON_STATE.lock().graph.style = style;
}

/// Set vertical scale
pub fn set_vertical_scale(min: u64, max: u64) {
    let mut state = PERFMON_STATE.lock();
    state.graph.vertical_min = min;
    state.graph.vertical_max = max;
    state.graph.auto_scale = false;
}

/// Enable auto-scale
pub fn set_auto_scale(enabled: bool) {
    PERFMON_STATE.lock().graph.auto_scale = enabled;
}

/// Set grid visibility
pub fn set_show_grid(show: bool) {
    PERFMON_STATE.lock().graph.show_grid = show;
}

/// Set update interval
pub fn set_update_interval(seconds: u32) {
    PERFMON_STATE.lock().graph.update_interval = seconds.max(1);
}

/// Set display duration
pub fn set_duration(seconds: u32) {
    PERFMON_STATE.lock().graph.duration = seconds.max(1);
}

// ============================================================================
// Monitoring Control
// ============================================================================

/// Start monitoring
pub fn start_monitoring() {
    PERFMON_STATE.lock().monitoring = true;
}

/// Stop monitoring
pub fn stop_monitoring() {
    PERFMON_STATE.lock().monitoring = false;
}

/// Is monitoring active
pub fn is_monitoring() -> bool {
    PERFMON_STATE.lock().monitoring
}

/// Clear all counter data
pub fn clear_data() {
    let mut state = PERFMON_STATE.lock();
    for i in 0..state.counter_count {
        state.counters[i].data_points = [0; MAX_DATA_POINTS];
        state.counters[i].data_index = 0;
        state.counters[i].data_count = 0;
        state.counters[i].current_value = 0;
        state.counters[i].average_value = 0;
        state.counters[i].min_value = u64::MAX;
        state.counters[i].max_value = 0;
    }
}

// ============================================================================
// Log Management
// ============================================================================

/// Create a performance log
pub fn create_log(name: &[u8], path: &[u8]) -> Option<u32> {
    let mut state = PERFMON_STATE.lock();
    if state.log_count >= MAX_LOGS {
        return None;
    }

    let log_id = state.next_log_id;
    state.next_log_id += 1;

    let mut log = LogConfig::new();
    log.log_id = log_id;
    log.set_name(name);
    log.set_path(path);

    let idx = state.log_count;
    state.logs[idx] = log;
    state.log_count += 1;

    Some(log_id)
}

/// Delete a performance log
pub fn delete_log(log_id: u32) -> bool {
    let mut state = PERFMON_STATE.lock();

    let mut found_index = None;
    for i in 0..state.log_count {
        if state.logs[i].log_id == log_id {
            found_index = Some(i);
            break;
        }
    }

    if let Some(index) = found_index {
        for i in index..state.log_count - 1 {
            state.logs[i] = state.logs[i + 1];
        }
        state.log_count -= 1;
        true
    } else {
        false
    }
}

/// Start a performance log
pub fn start_log(log_id: u32) -> bool {
    let mut state = PERFMON_STATE.lock();
    for i in 0..state.log_count {
        if state.logs[i].log_id == log_id {
            state.logs[i].running = true;
            return true;
        }
    }
    false
}

/// Stop a performance log
pub fn stop_log(log_id: u32) -> bool {
    let mut state = PERFMON_STATE.lock();
    for i in 0..state.log_count {
        if state.logs[i].log_id == log_id {
            state.logs[i].running = false;
            return true;
        }
    }
    false
}

/// Get log count
pub fn get_log_count() -> usize {
    PERFMON_STATE.lock().log_count
}

/// Get log by index
pub fn get_log(index: usize) -> Option<LogConfig> {
    let state = PERFMON_STATE.lock();
    if index < state.log_count {
        Some(state.logs[index])
    } else {
        None
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Performance Monitor statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct PerfmonStats {
    pub initialized: bool,
    pub counter_count: usize,
    pub log_count: usize,
    pub sample_count: u64,
    pub monitoring: bool,
}

/// Get Performance Monitor statistics
pub fn get_stats() -> PerfmonStats {
    let state = PERFMON_STATE.lock();
    PerfmonStats {
        initialized: PERFMON_INITIALIZED.load(Ordering::Relaxed),
        counter_count: state.counter_count,
        log_count: state.log_count,
        sample_count: SAMPLE_COUNT.load(Ordering::Relaxed),
        monitoring: state.monitoring,
    }
}

// ============================================================================
// Dialog Support
// ============================================================================

/// Performance Monitor dialog handle
pub type HPERFMONDLG = UserHandle;

static NEXT_DIALOG_ID: AtomicU32 = AtomicU32::new(1);

/// Create Performance Monitor dialog
pub fn create_perfmon_dialog(_parent: super::super::HWND) -> HPERFMONDLG {
    let id = NEXT_DIALOG_ID.fetch_add(1, Ordering::Relaxed);
    UserHandle::from_raw(id)
}
