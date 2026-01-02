//! Regional Settings Dialog
//!
//! Provides regional and language options following Windows
//! intl.cpl patterns.
//!
//! # References
//!
//! - Windows Server 2003 Regional and Language Options
//! - GetLocaleInfo/SetLocaleInfo APIs

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{HWND, UserHandle};

// ============================================================================
// Constants
// ============================================================================

/// Maximum name length
pub const MAX_NAME: usize = 64;

/// Locale ID type
pub type LCID = u32;

/// Default locale IDs
pub mod lcid {
    /// English (United States)
    pub const EN_US: u32 = 0x0409;
    /// English (United Kingdom)
    pub const EN_GB: u32 = 0x0809;
    /// German (Germany)
    pub const DE_DE: u32 = 0x0407;
    /// French (France)
    pub const FR_FR: u32 = 0x040C;
    /// Spanish (Spain)
    pub const ES_ES: u32 = 0x0C0A;
    /// Italian (Italy)
    pub const IT_IT: u32 = 0x0410;
    /// Portuguese (Brazil)
    pub const PT_BR: u32 = 0x0416;
    /// Russian (Russia)
    pub const RU_RU: u32 = 0x0419;
    /// Japanese (Japan)
    pub const JA_JP: u32 = 0x0411;
    /// Chinese (Simplified)
    pub const ZH_CN: u32 = 0x0804;
    /// Korean (Korea)
    pub const KO_KR: u32 = 0x0412;
}

/// Locale info types (LOCALE_*)
pub mod locale_info {
    /// Language name
    pub const SLANGUAGE: u32 = 0x00000002;
    /// Country name
    pub const SCOUNTRY: u32 = 0x00000006;
    /// English language name
    pub const SENGLANGUAGE: u32 = 0x00001001;
    /// English country name
    pub const SENGCOUNTRY: u32 = 0x00001002;
    /// Abbreviated language name
    pub const SABBREVLANGNAME: u32 = 0x00000003;
    /// Native language name
    pub const SNATIVELANGNAME: u32 = 0x00000004;
    /// ISO language name
    pub const SISO639LANGNAME: u32 = 0x00000059;
    /// ISO country name
    pub const SISO3166CTRYNAME: u32 = 0x0000005A;
    /// Decimal separator
    pub const SDECIMAL: u32 = 0x0000000E;
    /// Thousand separator
    pub const STHOUSAND: u32 = 0x0000000F;
    /// List separator
    pub const SLIST: u32 = 0x0000000C;
    /// Currency symbol
    pub const SCURRENCY: u32 = 0x00000014;
    /// Monetary decimal separator
    pub const SMONDECIMALSEP: u32 = 0x00000016;
    /// Monetary thousand separator
    pub const SMONTHOUSANDSEP: u32 = 0x00000017;
    /// Short date format
    pub const SSHORTDATE: u32 = 0x0000001F;
    /// Long date format
    pub const SLONGDATE: u32 = 0x00000020;
    /// Time format
    pub const STIMEFORMAT: u32 = 0x00001003;
    /// AM symbol
    pub const S1159: u32 = 0x00000028;
    /// PM symbol
    pub const S2359: u32 = 0x00000029;
    /// First day of week
    pub const IFIRSTDAYOFWEEK: u32 = 0x0000100C;
    /// Measurement system (0=metric, 1=US)
    pub const IMEASURE: u32 = 0x0000000D;
    /// Negative number format
    pub const INEGNUMBER: u32 = 0x00001010;
    /// Currency digits
    pub const ICURRDIGITS: u32 = 0x00000019;
}

// ============================================================================
// Structures
// ============================================================================

/// Locale info
#[derive(Clone, Copy)]
pub struct LocaleInfo {
    /// Locale ID
    pub lcid: LCID,
    /// Language name length
    pub language_len: u8,
    /// Language name
    pub language: [u8; MAX_NAME],
    /// Country name length
    pub country_len: u8,
    /// Country name
    pub country: [u8; MAX_NAME],
    /// Decimal separator
    pub decimal_sep: u8,
    /// Thousand separator
    pub thousand_sep: u8,
    /// List separator
    pub list_sep: u8,
    /// Currency symbol length
    pub currency_len: u8,
    /// Currency symbol
    pub currency: [u8; 8],
    /// Currency digits after decimal
    pub currency_digits: u8,
    /// Measurement system (0=metric, 1=US)
    pub measurement: u8,
    /// First day of week (0=Monday, 6=Sunday)
    pub first_day: u8,
    /// 12-hour time format
    pub time_12h: bool,
    /// AM symbol length
    pub am_len: u8,
    /// AM symbol
    pub am: [u8; 8],
    /// PM symbol length
    pub pm_len: u8,
    /// PM symbol
    pub pm: [u8; 8],
    /// Short date format length
    pub short_date_len: u8,
    /// Short date format
    pub short_date: [u8; 32],
    /// Long date format length
    pub long_date_len: u8,
    /// Long date format
    pub long_date: [u8; 64],
    /// Time format length
    pub time_format_len: u8,
    /// Time format
    pub time_format: [u8; 32],
}

impl LocaleInfo {
    const fn new() -> Self {
        Self {
            lcid: lcid::EN_US,
            language_len: 0,
            language: [0; MAX_NAME],
            country_len: 0,
            country: [0; MAX_NAME],
            decimal_sep: b'.',
            thousand_sep: b',',
            list_sep: b',',
            currency_len: 0,
            currency: [0; 8],
            currency_digits: 2,
            measurement: 1, // US
            first_day: 6, // Sunday
            time_12h: true,
            am_len: 0,
            am: [0; 8],
            pm_len: 0,
            pm: [0; 8],
            short_date_len: 0,
            short_date: [0; 32],
            long_date_len: 0,
            long_date: [0; 64],
            time_format_len: 0,
            time_format: [0; 32],
        }
    }
}

/// Locale entry
#[derive(Clone, Copy)]
pub struct LocaleEntry {
    /// Entry is valid
    pub valid: bool,
    /// Locale ID
    pub lcid: LCID,
    /// Display name length
    pub display_name_len: u8,
    /// Display name
    pub display_name: [u8; 128],
    /// Locale info
    pub info: LocaleInfo,
}

impl LocaleEntry {
    const fn new() -> Self {
        Self {
            valid: false,
            lcid: 0,
            display_name_len: 0,
            display_name: [0; 128],
            info: LocaleInfo::new(),
        }
    }
}

/// Number format
#[derive(Clone, Copy)]
pub struct NumberFormat {
    /// Number of decimal digits
    pub num_digits: u32,
    /// Leading zero (0=no, 1=yes)
    pub leading_zero: u32,
    /// Grouping (e.g., 3 for 1,000)
    pub grouping: u32,
    /// Decimal separator
    pub decimal_sep: u8,
    /// Thousand separator
    pub thousand_sep: u8,
    /// Negative format
    pub negative_order: u32,
}

impl NumberFormat {
    pub const fn new() -> Self {
        Self {
            num_digits: 2,
            leading_zero: 1,
            grouping: 3,
            decimal_sep: b'.',
            thousand_sep: b',',
            negative_order: 1,
        }
    }
}

/// Currency format
#[derive(Clone, Copy)]
pub struct CurrencyFormat {
    /// Number of decimal digits
    pub num_digits: u32,
    /// Leading zero
    pub leading_zero: u32,
    /// Grouping
    pub grouping: u32,
    /// Decimal separator
    pub decimal_sep: u8,
    /// Thousand separator
    pub thousand_sep: u8,
    /// Positive format (0-3)
    pub positive_order: u32,
    /// Negative format (0-15)
    pub negative_order: u32,
    /// Currency symbol length
    pub symbol_len: u8,
    /// Currency symbol
    pub symbol: [u8; 8],
}

impl CurrencyFormat {
    pub const fn new() -> Self {
        Self {
            num_digits: 2,
            leading_zero: 1,
            grouping: 3,
            decimal_sep: b'.',
            thousand_sep: b',',
            positive_order: 0,
            negative_order: 0,
            symbol_len: 1,
            symbol: [b'$', 0, 0, 0, 0, 0, 0, 0],
        }
    }
}

/// Regional dialog state
#[derive(Clone, Copy)]
pub struct RegionalDialogState {
    /// Dialog is active
    pub active: bool,
    /// Dialog handle
    pub hwnd: HWND,
    /// Current tab
    pub current_tab: u8,
    /// Pending locale
    pub pending_lcid: LCID,
    /// Changes pending
    pub changes_pending: bool,
}

impl RegionalDialogState {
    const fn new() -> Self {
        Self {
            active: false,
            hwnd: UserHandle::NULL,
            current_tab: 0,
            pending_lcid: lcid::EN_US,
            changes_pending: false,
        }
    }
}

// ============================================================================
// State
// ============================================================================

static REGIONAL_INITIALIZED: AtomicBool = AtomicBool::new(false);
static REGIONAL_LOCK: SpinLock<()> = SpinLock::new(());
static CURRENT_LCID: AtomicU32 = AtomicU32::new(lcid::EN_US);

static CURRENT_LOCALE: SpinLock<LocaleInfo> = SpinLock::new(LocaleInfo::new());
static NUMBER_FORMAT: SpinLock<NumberFormat> = SpinLock::new(NumberFormat::new());
static CURRENCY_FORMAT: SpinLock<CurrencyFormat> = SpinLock::new(CurrencyFormat::new());

// Available locales
const MAX_LOCALES: usize = 32;
static LOCALES: SpinLock<[LocaleEntry; MAX_LOCALES]> =
    SpinLock::new([const { LocaleEntry::new() }; MAX_LOCALES]);

// Dialog state
static DIALOG_STATE: SpinLock<RegionalDialogState> = SpinLock::new(RegionalDialogState::new());

// ============================================================================
// Initialization
// ============================================================================

/// Initialize regional settings subsystem
pub fn init() {
    let _guard = REGIONAL_LOCK.lock();

    if REGIONAL_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[REGIONAL] Initializing regional settings...");

    // Initialize available locales
    init_locales();

    // Set default locale (English US)
    set_locale_internal(lcid::EN_US);

    REGIONAL_INITIALIZED.store(true, Ordering::Release);
    crate::serial_println!("[REGIONAL] Regional settings initialized");
}

/// Initialize available locales
fn init_locales() {
    let locale_data: &[(LCID, &[u8], &[u8], &[u8], u8, u8, &[u8], &[u8])] = &[
        (lcid::EN_US, b"English (United States)", b"English", b"United States", b'.', b',', b"$", b"M/d/yyyy"),
        (lcid::EN_GB, b"English (United Kingdom)", b"English", b"United Kingdom", b'.', b',', b"\xc2\xa3", b"dd/MM/yyyy"),
        (lcid::DE_DE, b"German (Germany)", b"Deutsch", b"Deutschland", b',', b'.', b"\xe2\x82\xac", b"dd.MM.yyyy"),
        (lcid::FR_FR, b"French (France)", b"Fran\xc3\xa7ais", b"France", b',', b' ', b"\xe2\x82\xac", b"dd/MM/yyyy"),
        (lcid::ES_ES, b"Spanish (Spain)", b"Espa\xc3\xb1ol", b"Espa\xc3\xb1a", b',', b'.', b"\xe2\x82\xac", b"dd/MM/yyyy"),
        (lcid::IT_IT, b"Italian (Italy)", b"Italiano", b"Italia", b',', b'.', b"\xe2\x82\xac", b"dd/MM/yyyy"),
        (lcid::PT_BR, b"Portuguese (Brazil)", b"Portugu\xc3\xaas", b"Brasil", b',', b'.', b"R$", b"dd/MM/yyyy"),
        (lcid::RU_RU, b"Russian (Russia)", b"\xd0\xa0\xd1\x83\xd1\x81\xd1\x81\xd0\xba\xd0\xb8\xd0\xb9", b"\xd0\xa0\xd0\xbe\xd1\x81\xd1\x81\xd0\xb8\xd1\x8f", b',', b' ', b"\xe2\x82\xbd", b"dd.MM.yyyy"),
        (lcid::JA_JP, b"Japanese (Japan)", b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e", b"\xe6\x97\xa5\xe6\x9c\xac", b'.', b',', b"\xc2\xa5", b"yyyy/MM/dd"),
        (lcid::ZH_CN, b"Chinese (Simplified, China)", b"\xe4\xb8\xad\xe6\x96\x87", b"\xe4\xb8\xad\xe5\x9b\xbd", b'.', b',', b"\xc2\xa5", b"yyyy/M/d"),
        (lcid::KO_KR, b"Korean (Korea)", b"\xed\x95\x9c\xea\xb5\xad\xec\x96\xb4", b"\xeb\x8c\x80\xed\x95\x9c\xeb\xaf\xbc\xea\xb5\xad", b'.', b',', b"\xe2\x82\xa9", b"yyyy-MM-dd"),
    ];

    let mut locales = LOCALES.lock();

    for (i, (lcid, display, lang, country, dec, thou, curr, date)) in locale_data.iter().enumerate() {
        if i >= MAX_LOCALES {
            break;
        }

        let locale = &mut locales[i];
        locale.valid = true;
        locale.lcid = *lcid;

        locale.display_name_len = display.len().min(128) as u8;
        locale.display_name[..locale.display_name_len as usize]
            .copy_from_slice(&display[..locale.display_name_len as usize]);

        locale.info.lcid = *lcid;
        locale.info.language_len = lang.len().min(MAX_NAME) as u8;
        locale.info.language[..locale.info.language_len as usize]
            .copy_from_slice(&lang[..locale.info.language_len as usize]);

        locale.info.country_len = country.len().min(MAX_NAME) as u8;
        locale.info.country[..locale.info.country_len as usize]
            .copy_from_slice(&country[..locale.info.country_len as usize]);

        locale.info.decimal_sep = *dec;
        locale.info.thousand_sep = *thou;

        locale.info.currency_len = curr.len().min(8) as u8;
        locale.info.currency[..locale.info.currency_len as usize]
            .copy_from_slice(&curr[..locale.info.currency_len as usize]);

        locale.info.short_date_len = date.len().min(32) as u8;
        locale.info.short_date[..locale.info.short_date_len as usize]
            .copy_from_slice(&date[..locale.info.short_date_len as usize]);
    }
}

/// Set locale internal (without lock)
fn set_locale_internal(lcid: LCID) {
    let locales = LOCALES.lock();

    for locale in locales.iter() {
        if locale.valid && locale.lcid == lcid {
            let mut current = CURRENT_LOCALE.lock();
            *current = locale.info;

            // Update number format
            let mut num_fmt = NUMBER_FORMAT.lock();
            num_fmt.decimal_sep = locale.info.decimal_sep;
            num_fmt.thousand_sep = locale.info.thousand_sep;

            // Update currency format
            let mut curr_fmt = CURRENCY_FORMAT.lock();
            curr_fmt.decimal_sep = locale.info.decimal_sep;
            curr_fmt.thousand_sep = locale.info.thousand_sep;
            curr_fmt.symbol_len = locale.info.currency_len;
            curr_fmt.symbol = locale.info.currency;

            CURRENT_LCID.store(lcid, Ordering::Release);
            return;
        }
    }
}

// ============================================================================
// Locale API
// ============================================================================

/// Get user default locale ID
pub fn get_user_default_lcid() -> LCID {
    CURRENT_LCID.load(Ordering::Acquire)
}

/// Get system default locale ID
pub fn get_system_default_lcid() -> LCID {
    lcid::EN_US
}

/// Set user locale
pub fn set_user_locale(lcid: LCID) -> bool {
    if !REGIONAL_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    // Validate LCID
    let locales = LOCALES.lock();
    let valid = locales.iter().any(|l| l.valid && l.lcid == lcid);
    drop(locales);

    if !valid {
        return false;
    }

    set_locale_internal(lcid);
    true
}

/// Get locale info
pub fn get_locale_info(lcid: LCID, info_type: u32, buffer: &mut [u8]) -> usize {
    let locales = LOCALES.lock();

    for locale in locales.iter() {
        if locale.valid && locale.lcid == lcid {
            return get_locale_info_internal(&locale.info, info_type, buffer);
        }
    }

    0
}

/// Get locale info internal
fn get_locale_info_internal(info: &LocaleInfo, info_type: u32, buffer: &mut [u8]) -> usize {
    match info_type {
        locale_info::SLANGUAGE | locale_info::SENGLANGUAGE => {
            let len = (info.language_len as usize).min(buffer.len());
            buffer[..len].copy_from_slice(&info.language[..len]);
            len
        }
        locale_info::SCOUNTRY | locale_info::SENGCOUNTRY => {
            let len = (info.country_len as usize).min(buffer.len());
            buffer[..len].copy_from_slice(&info.country[..len]);
            len
        }
        locale_info::SDECIMAL => {
            if !buffer.is_empty() {
                buffer[0] = info.decimal_sep;
                1
            } else {
                0
            }
        }
        locale_info::STHOUSAND => {
            if !buffer.is_empty() {
                buffer[0] = info.thousand_sep;
                1
            } else {
                0
            }
        }
        locale_info::SLIST => {
            if !buffer.is_empty() {
                buffer[0] = info.list_sep;
                1
            } else {
                0
            }
        }
        locale_info::SCURRENCY => {
            let len = (info.currency_len as usize).min(buffer.len());
            buffer[..len].copy_from_slice(&info.currency[..len]);
            len
        }
        locale_info::SSHORTDATE => {
            let len = (info.short_date_len as usize).min(buffer.len());
            buffer[..len].copy_from_slice(&info.short_date[..len]);
            len
        }
        locale_info::SLONGDATE => {
            let len = (info.long_date_len as usize).min(buffer.len());
            buffer[..len].copy_from_slice(&info.long_date[..len]);
            len
        }
        locale_info::STIMEFORMAT => {
            let len = (info.time_format_len as usize).min(buffer.len());
            buffer[..len].copy_from_slice(&info.time_format[..len]);
            len
        }
        locale_info::S1159 => {
            let len = (info.am_len as usize).min(buffer.len());
            buffer[..len].copy_from_slice(&info.am[..len]);
            len
        }
        locale_info::S2359 => {
            let len = (info.pm_len as usize).min(buffer.len());
            buffer[..len].copy_from_slice(&info.pm[..len]);
            len
        }
        locale_info::IMEASURE => {
            if !buffer.is_empty() {
                buffer[0] = b'0' + info.measurement;
                1
            } else {
                0
            }
        }
        _ => 0,
    }
}

/// Get current locale info
pub fn get_current_locale() -> LocaleInfo {
    *CURRENT_LOCALE.lock()
}

/// Get available locales
pub fn get_available_locales() -> ([LocaleEntry; MAX_LOCALES], usize) {
    let locales = LOCALES.lock();
    let count = locales.iter().filter(|l| l.valid).count();
    (*locales, count)
}

// ============================================================================
// Number Formatting
// ============================================================================

/// Get number format
pub fn get_number_format() -> NumberFormat {
    *NUMBER_FORMAT.lock()
}

/// Set number format
pub fn set_number_format(format: &NumberFormat) {
    let mut fmt = NUMBER_FORMAT.lock();
    *fmt = *format;
}

/// Format number
pub fn format_number(value: i64, buffer: &mut [u8]) -> usize {
    let fmt = NUMBER_FORMAT.lock();
    format_number_internal(value, &fmt, buffer)
}

/// Format number internal
fn format_number_internal(value: i64, fmt: &NumberFormat, buffer: &mut [u8]) -> usize {
    let negative = value < 0;
    let abs_value = value.unsigned_abs();

    let mut temp = [0u8; 32];
    let mut temp_len = 0;

    // Format digits
    let mut n = abs_value;
    if n == 0 {
        temp[0] = b'0';
        temp_len = 1;
    } else {
        while n > 0 && temp_len < 32 {
            temp[temp_len] = b'0' + (n % 10) as u8;
            n /= 10;
            temp_len += 1;
        }
    }

    let mut pos = 0;

    // Negative sign
    if negative && pos < buffer.len() {
        buffer[pos] = b'-';
        pos += 1;
    }

    // Insert with thousand separators
    let group = fmt.grouping as usize;
    for i in 0..temp_len {
        if group > 0 && i > 0 && i % group == 0 && pos < buffer.len() {
            buffer[pos] = fmt.thousand_sep;
            pos += 1;
        }
        if pos < buffer.len() {
            buffer[pos] = temp[temp_len - 1 - i];
            pos += 1;
        }
    }

    pos
}

// ============================================================================
// Currency Formatting
// ============================================================================

/// Get currency format
pub fn get_currency_format() -> CurrencyFormat {
    *CURRENCY_FORMAT.lock()
}

/// Set currency format
pub fn set_currency_format(format: &CurrencyFormat) {
    let mut fmt = CURRENCY_FORMAT.lock();
    *fmt = *format;
}

/// Format currency
pub fn format_currency(value: i64, buffer: &mut [u8]) -> usize {
    let fmt = CURRENCY_FORMAT.lock();
    format_currency_internal(value, &fmt, buffer)
}

/// Format currency internal
fn format_currency_internal(value: i64, fmt: &CurrencyFormat, buffer: &mut [u8]) -> usize {
    let mut pos = 0;

    // Currency symbol first (positive_order == 0)
    if fmt.positive_order == 0 {
        let sym_len = (fmt.symbol_len as usize).min(buffer.len() - pos);
        buffer[pos..pos + sym_len].copy_from_slice(&fmt.symbol[..sym_len]);
        pos += sym_len;
    }

    // Format the number
    let num_fmt = NumberFormat {
        num_digits: fmt.num_digits,
        leading_zero: fmt.leading_zero,
        grouping: fmt.grouping,
        decimal_sep: fmt.decimal_sep,
        thousand_sep: fmt.thousand_sep,
        negative_order: fmt.negative_order,
    };
    pos += format_number_internal(value, &num_fmt, &mut buffer[pos..]);

    // Currency symbol after (positive_order != 0)
    if fmt.positive_order != 0 && pos < buffer.len() {
        let sym_len = (fmt.symbol_len as usize).min(buffer.len() - pos);
        buffer[pos..pos + sym_len].copy_from_slice(&fmt.symbol[..sym_len]);
        pos += sym_len;
    }

    pos
}

// ============================================================================
// Regional Dialog
// ============================================================================

/// Show regional settings dialog
pub fn show_regional_dialog(hwnd_owner: HWND, tab: u8) -> bool {
    if !REGIONAL_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut state = DIALOG_STATE.lock();

    if state.active {
        return false;
    }

    state.current_tab = tab;
    state.pending_lcid = get_user_default_lcid();
    state.changes_pending = false;

    let hwnd = create_regional_dialog(hwnd_owner);

    if hwnd == UserHandle::NULL {
        return false;
    }

    state.active = true;
    state.hwnd = hwnd;

    drop(state);

    let result = run_regional_dialog(hwnd);

    if result {
        apply_regional_changes();
    }

    let mut state = DIALOG_STATE.lock();
    state.active = false;
    state.hwnd = UserHandle::NULL;

    result
}

/// Close regional dialog
pub fn close_regional_dialog() {
    let mut state = DIALOG_STATE.lock();

    if state.active {
        if state.hwnd != UserHandle::NULL {
            super::window::destroy_window(state.hwnd);
        }
        state.active = false;
        state.hwnd = UserHandle::NULL;
    }
}

/// Apply pending changes
fn apply_regional_changes() {
    let state = DIALOG_STATE.lock();

    if !state.changes_pending {
        return;
    }

    let lcid = state.pending_lcid;
    drop(state);

    set_user_locale(lcid);
}

// Dialog creation/run stubs
fn create_regional_dialog(_owner: HWND) -> HWND { UserHandle::NULL }
fn run_regional_dialog(_hwnd: HWND) -> bool { true }

/// Regional dialog procedure
pub fn regional_dialog_proc(hwnd: HWND, msg: u32, wparam: usize, _lparam: isize) -> isize {
    match msg {
        super::message::WM_COMMAND => handle_regional_command(hwnd, wparam as u32),
        super::message::WM_CLOSE => { close_regional_dialog(); 0 }
        _ => 0,
    }
}

fn handle_regional_command(hwnd: HWND, command: u32) -> isize {
    let id = command as u16;
    match id {
        1 => { // OK
            let state = DIALOG_STATE.lock();
            if state.active && state.hwnd == hwnd {
                drop(state);
                apply_regional_changes();
                close_regional_dialog();
            }
            0
        }
        2 => { close_regional_dialog(); 0 } // Cancel
        3 => { apply_regional_changes(); 0 } // Apply
        100 => { // Locale combo changed
            let mut state = DIALOG_STATE.lock();
            state.pending_lcid = (command >> 16) as LCID;
            state.changes_pending = true;
            0
        }
        _ => 0,
    }
}
