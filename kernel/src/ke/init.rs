//! Kernel Executive Initialization
//!
//! This module provides initialization routines for the kernel executive,
//! including the scheduler, PRCB, KPCR, threads, and timer.

use core::sync::atomic::{AtomicU32, Ordering};
use crate::hal::apic;
use crate::arch::x86_64::idt::vector;
use super::prcb;
use super::kpcr;
use super::process;
use super::idle;
use super::thread::{KThread, constants};
use super::timer;

/// Timer frequency in Hz (1000 = 1ms tick)
const TIMER_FREQUENCY_HZ: u32 = 1000;

/// Thread stack pool
static mut THREAD_STACK_POOL: [[u8; constants::THREAD_STACK_SIZE]; constants::MAX_THREADS] =
    [[0; constants::THREAD_STACK_SIZE]; constants::MAX_THREADS];

/// Next available stack index
static NEXT_STACK: AtomicU32 = AtomicU32::new(1); // 0 is reserved for idle

/// Initialize the kernel executive (phase 1)
///
/// This is called during kernel initialization after basic
/// architecture setup (GDT, IDT, memory) is complete.
///
/// # Safety
/// Must be called exactly once during kernel boot
pub unsafe fn init() {
    // Initialize the processor control block (KPRCB)
    prcb::init_bsp_prcb();

    // Initialize the processor control region (KPCR)
    // Get pointer to BSP's PRCB for KPCR initialization
    let bsp_prcb = prcb::ki_get_processor_block(0);
    kpcr::init_kpcr(0, bsp_prcb);

    // Lower IRQL to PASSIVE_LEVEL now that we're initialized
    kpcr::ke_lower_irql(kpcr::irql::PASSIVE_LEVEL);

    // Initialize the system process (process 0)
    process::init_system_process();

    // Initialize the idle thread for CPU 0 (BSP)
    idle::init_idle_thread(0);

    // Initialize and start the APIC timer
    apic::init();
    apic::start_timer(vector::TIMER, TIMER_FREQUENCY_HZ);

    // Initialize the timer subsystem
    timer::ki_init_timer_system();

    crate::kprintln!("[KE] Kernel executive initialized");
    crate::serial_println!("[KE] Kernel executive initialized");
    crate::serial_println!("[KE] KPRCB and KPCR initialized for BSP");
    crate::kprintln!("[KE] APIC timer running at {} Hz", TIMER_FREQUENCY_HZ);
    crate::serial_println!("[KE] APIC timer running at {} Hz", TIMER_FREQUENCY_HZ);
}

/// Create and start a kernel thread
///
/// # Arguments
/// * `priority` - Thread priority (0-31)
/// * `entry` - Thread entry point function
///
/// # Safety
/// Must be called before interrupts are enabled or with proper synchronization
pub unsafe fn create_thread(
    priority: i8,
    entry: fn(),
) -> Option<*mut KThread> {
    use super::thread::allocate_thread;
    use crate::arch::x86_64::context::setup_initial_context;

    // Allocate a thread from the pool
    let thread = allocate_thread()?;

    // Get next stack index
    let stack_index = NEXT_STACK.fetch_add(1, Ordering::SeqCst) as usize;
    if stack_index >= constants::MAX_THREADS {
        return None;
    }

    let stack_base = THREAD_STACK_POOL[stack_index].as_mut_ptr()
        .add(constants::THREAD_STACK_SIZE);

    // Initialize thread structure
    (*thread).thread_id = stack_index as u32;
    (*thread).priority = priority;
    (*thread).base_priority = priority;
    (*thread).quantum = constants::THREAD_QUANTUM;
    (*thread).stack_base = stack_base;
    (*thread).stack_limit = THREAD_STACK_POOL[stack_index].as_mut_ptr();
    (*thread).process = process::get_system_process_mut();
    (*thread).state = super::thread::ThreadState::Initialized;
    (*thread).wait_list_entry.init_head();
    (*thread).thread_list_entry.init_head();

    // Initialize APC state
    (*thread).apc_state.init(process::get_system_process_mut());
    (*thread).special_apc_disable = 0;
    (*thread).kernel_apc_disable = 0;
    (*thread).alertable = false;
    (*thread).apc_queueable = true;

    // Set up initial context to jump to entry point
    setup_initial_context(thread, stack_base, entry);

    // Ready the thread
    super::scheduler::ki_ready_thread(thread);

    crate::serial_println!("[KE] Created thread {} at priority {}", stack_index, priority);

    Some(thread)
}

/// Start the scheduler
///
/// This enables interrupts and begins normal scheduling.
/// After this call, the timer will fire and threads will be scheduled.
///
/// # Safety
/// Must be called after init() and with the idle thread set up
pub unsafe fn start_scheduler() {
    crate::kprintln!("[KE] Starting scheduler...");
    crate::serial_println!("[KE] Starting scheduler...");

    // Debug: print ready summary before enabling interrupts
    let prcb = prcb::get_current_prcb();
    crate::serial_println!("[KE] Ready summary: {:#x}", prcb.ready_summary);
    crate::serial_println!("[KE] Current thread: {:?}", prcb.current_thread);
    crate::serial_println!("[KE] Idle thread: {:?}", prcb.idle_thread);

    crate::serial_println!("[KE] Enabling interrupts...");

    // Enable interrupts to start receiving timer ticks
    crate::arch::x86_64::enable_interrupts();

    crate::serial_println!("[KE] Interrupts enabled!");
    crate::kprintln!("[KE] Scheduler running");
    crate::serial_println!("[KE] Scheduler running");
}

// ============================================================================
// Test Threads
// ============================================================================

use super::timer::{KTimer, TimerType};
use super::dpc::KDpc;

// ============================================================================
// Timer Test - Kernel Timer Demonstration
// ============================================================================

/// Test timers with different configurations
static mut ONESHOT_TIMER: KTimer = KTimer::new();
static mut PERIODIC_TIMER: KTimer = KTimer::new();
static mut DPC_TIMER: KTimer = KTimer::new();

/// DPC for timer callback
static mut TIMER_DPC: KDpc = KDpc::new();

/// Counters for timer tracking
static mut ONESHOT_EXPIRATIONS: u32 = 0;
static mut PERIODIC_EXPIRATIONS: u32 = 0;
static mut TIMER_DPC_COUNT: u32 = 0;
static mut LAST_PERIODIC_TIME: u64 = 0;

/// DPC routine called when DPC_TIMER expires
fn timer_dpc_routine(
    _dpc: *mut KDpc,
    context: usize,
    _arg1: usize,
    _arg2: usize,
) {
    unsafe {
        TIMER_DPC_COUNT += 1;
    }
    let ticks = apic::get_tick_count();
    crate::serial_println!("[TIMER-DPC] Fired! count={}, ticks={}, context={}",
        unsafe { TIMER_DPC_COUNT }, ticks, context);
}

/// Initialize the timer test resources
fn init_timer_test() {
    unsafe {
        // Zero structures (workaround for unzeroed .bss)
        let zero_struct = |ptr: *mut u8, size: usize| {
            for i in 0..size {
                core::ptr::write_volatile(ptr.add(i), 0);
            }
        };

        zero_struct(&ONESHOT_TIMER as *const _ as *mut u8, core::mem::size_of::<KTimer>());
        zero_struct(&PERIODIC_TIMER as *const _ as *mut u8, core::mem::size_of::<KTimer>());
        zero_struct(&DPC_TIMER as *const _ as *mut u8, core::mem::size_of::<KTimer>());
        zero_struct(&TIMER_DPC as *const _ as *mut u8, core::mem::size_of::<KDpc>());

        // Initialize timers
        ONESHOT_TIMER.init_ex(TimerType::Notification);
        PERIODIC_TIMER.init_ex(TimerType::Notification);
        DPC_TIMER.init_ex(TimerType::Notification);

        // Initialize timer DPC
        TIMER_DPC.init(timer_dpc_routine, 12345);

        // Reset counters
        ONESHOT_EXPIRATIONS = 0;
        PERIODIC_EXPIRATIONS = 0;
        TIMER_DPC_COUNT = 0;
        LAST_PERIODIC_TIME = 0;
    }
    crate::serial_println!("[KE] Timer test initialized");
    crate::serial_println!("[KE]   One-shot, Periodic, and DPC-linked timers");
}

/// Worker thread that sets and monitors timers
fn timer_worker_thread() {
    let thread_id = unsafe {
        let prcb = super::prcb::get_current_prcb();
        (*prcb.current_thread).thread_id
    };

    crate::serial_println!("[Worker {}] Started - timer test", thread_id);

    match thread_id {
        1 => oneshot_timer_worker(),
        2 => periodic_timer_worker(),
        _ => dpc_timer_worker(),
    }
}

/// Worker 1: Tests one-shot timers
fn oneshot_timer_worker() {
    let mut iteration = 0u32;

    loop {
        iteration += 1;

        // Set a one-shot timer for 500ms
        let set_time = apic::get_tick_count();
        unsafe {
            ONESHOT_TIMER.set_simple(500);
        }
        crate::serial_println!("[OneShot] Set timer #{} at ticks={}", iteration, set_time);

        // Wait for timer to expire by polling
        loop {
            if unsafe { ONESHOT_TIMER.is_signaled() } {
                let expire_time = apic::get_tick_count();
                let elapsed = expire_time - set_time;
                unsafe { ONESHOT_EXPIRATIONS += 1; }
                crate::serial_println!("[OneShot] Timer #{} expired! elapsed={}ms, total={}",
                    iteration, elapsed, unsafe { ONESHOT_EXPIRATIONS });
                break;
            }
            // Small delay
            for _ in 0..1000 {
                core::hint::spin_loop();
            }
        }

        // Pause before next timer
        for _ in 0..200000 {
            core::hint::spin_loop();
        }
    }
}

/// Worker 2: Tests periodic timers
fn periodic_timer_worker() {
    // Set a periodic timer for every 1000ms
    let start_time = apic::get_tick_count();
    unsafe {
        PERIODIC_TIMER.set(1000, 1000, None);
        LAST_PERIODIC_TIME = start_time;
    }
    crate::serial_println!("[Periodic] Started periodic timer (1000ms interval)");

    loop {
        // Wait for timer to become signaled
        if unsafe { PERIODIC_TIMER.is_signaled() } {
            let now = apic::get_tick_count();
            let interval = now - unsafe { LAST_PERIODIC_TIME };
            unsafe {
                PERIODIC_EXPIRATIONS += 1;
                LAST_PERIODIC_TIME = now;
                // Clear the signal to acknowledge this expiration
                // The timer will become signaled again on next period
                PERIODIC_TIMER.clear_signal();
            }
            crate::serial_println!("[Periodic] Tick #{} at ticks={}, interval={}ms",
                unsafe { PERIODIC_EXPIRATIONS }, now, interval);
        }

        // Small delay
        for _ in 0..5000 {
            core::hint::spin_loop();
        }
    }
}

/// Worker 3: Tests timers with DPC callbacks
fn dpc_timer_worker() {
    let mut iteration = 0u32;

    loop {
        iteration += 1;

        // Set a timer that will fire a DPC after 750ms
        let set_time = apic::get_tick_count();
        unsafe {
            DPC_TIMER.set(750, 0, Some(&TIMER_DPC));
        }
        crate::serial_println!("[DPC-Timer] Set timer #{} with DPC at ticks={}", iteration, set_time);

        // Wait for DPC to fire
        let expected_dpc_count = iteration;
        loop {
            if unsafe { TIMER_DPC_COUNT >= expected_dpc_count } {
                break;
            }
            // Small delay
            for _ in 0..5000 {
                core::hint::spin_loop();
            }
        }

        // Pause before next timer
        for _ in 0..300000 {
            core::hint::spin_loop();
        }
    }
}

/// Monitor thread - reports timer state
fn timer_monitor_thread() {
    crate::serial_println!("[Monitor] Started - tracking timer expirations");

    let mut last_report = 0u64;

    loop {
        let ticks = apic::get_tick_count();

        // Report every 3 seconds
        if ticks >= last_report + 3000 {
            let (oneshot, periodic, dpc_count, active) = unsafe {
                (ONESHOT_EXPIRATIONS, PERIODIC_EXPIRATIONS, TIMER_DPC_COUNT,
                 timer::ki_get_active_timer_count())
            };

            crate::serial_println!("[Monitor] ==================");
            crate::serial_println!("[Monitor] ticks={}", ticks);
            crate::serial_println!("[Monitor]   Active timers: {}", active);
            crate::serial_println!("[Monitor]   One-shot expirations: {}", oneshot);
            crate::serial_println!("[Monitor]   Periodic expirations: {}", periodic);
            crate::serial_println!("[Monitor]   Timer DPC fires: {}", dpc_count);
            crate::serial_println!("[Monitor] ==================");
            last_report = ticks;
        }

        // Small delay
        for _ in 0..5000 {
            core::hint::spin_loop();
        }
    }
}

/// Create test threads to verify timer functionality
///
/// # Safety
/// Must be called after init() but before start_scheduler()
pub unsafe fn create_test_threads() {
    crate::serial_println!("[KE] Creating timer test threads...");

    // Initialize the timer test resources
    init_timer_test();

    // Create 3 worker threads for different timer tests
    for i in 1..=3 {
        if create_thread(8, timer_worker_thread).is_some() {
            crate::serial_println!("[KE] Timer worker thread {} created", i);
        } else {
            crate::serial_println!("[KE] ERROR: Failed to create timer worker {}", i);
        }
    }

    // Create monitor thread
    if create_thread(8, timer_monitor_thread).is_some() {
        crate::serial_println!("[KE] Timer monitor thread created");
    } else {
        crate::serial_println!("[KE] ERROR: Failed to create timer monitor thread");
    }

    crate::serial_println!("[KE] Timer test threads created");
    crate::serial_println!("[KE]   Worker 1: One-shot timers (500ms)");
    crate::serial_println!("[KE]   Worker 2: Periodic timer (1000ms)");
    crate::serial_println!("[KE]   Worker 3: Timer with DPC (750ms)");

    // Create APC test thread
    if create_thread(8, apc_test_thread).is_some() {
        crate::serial_println!("[KE] APC test thread created");
    }
}

// ============================================================================
// APC Test - Asynchronous Procedure Call Demonstration
// ============================================================================

use super::apc::{KApc, ApcMode};
use super::event::{KEvent, EventType};
use super::semaphore::KSemaphore;
use super::dispatcher::{DispatcherHeader, WaitType, WaitStatus};
use super::wait;

/// Static APCs for testing
static mut TEST_APCS: [KApc; 4] = [KApc::new(), KApc::new(), KApc::new(), KApc::new()];

/// APC delivery counter
static mut APC_DELIVERY_COUNT: u32 = 0;

/// Kernel APC routine - called at APC_LEVEL
fn test_kernel_routine(
    _apc: *mut KApc,
    normal_routine: *mut Option<super::apc::NormalRoutine>,
    normal_context: *mut usize,
    _system_argument1: *mut usize,
    _system_argument2: *mut usize,
) {
    unsafe {
        APC_DELIVERY_COUNT += 1;
        let count = APC_DELIVERY_COUNT;
        let ctx = *normal_context;
        crate::serial_println!("[APC-Kernel] Kernel routine #{}, context={}", count, ctx);

        // Optionally modify or cancel the normal routine
        // For this test, we let it proceed
        let _ = normal_routine;
    }
}

/// Normal APC routine - called after kernel routine
fn test_normal_routine(
    normal_context: usize,
    system_argument1: usize,
    system_argument2: usize,
) {
    crate::serial_println!("[APC-Normal] Normal routine: ctx={}, arg1={}, arg2={}",
        normal_context, system_argument1, system_argument2);
}

/// Special kernel APC routine (no normal routine)
fn test_special_kernel_routine(
    _apc: *mut KApc,
    _normal_routine: *mut Option<super::apc::NormalRoutine>,
    _normal_context: *mut usize,
    system_argument1: *mut usize,
    _system_argument2: *mut usize,
) {
    unsafe {
        APC_DELIVERY_COUNT += 1;
        let arg1 = *system_argument1;
        crate::serial_println!("[APC-Special] Special kernel APC delivered! arg1={}", arg1);
    }
}

/// APC test thread - queues APCs to itself
fn apc_test_thread() {
    let thread_id = unsafe {
        let prcb = super::prcb::get_current_prcb();
        (*prcb.current_thread).thread_id
    };

    crate::serial_println!("[APC-Test] Thread {} started - APC test", thread_id);

    // Get pointer to current thread
    let current_thread = super::prcb::get_current_prcb().current_thread;

    // Initialize and zero the APCs
    unsafe {
        for apc in TEST_APCS.iter() {
            let ptr = apc as *const _ as *mut u8;
            for i in 0..core::mem::size_of::<KApc>() {
                core::ptr::write_volatile(ptr.add(i), 0);
            }
        }
    }

    let mut iteration = 0u32;

    loop {
        iteration += 1;
        let ticks = apic::get_tick_count();

        // Every 2 seconds, queue some APCs
        if iteration % 200 == 1 {
            crate::serial_println!("[APC-Test] Queuing APCs at ticks={}", ticks);

            unsafe {
                // Queue a normal kernel APC with normal routine
                TEST_APCS[0].init(
                    current_thread,
                    test_kernel_routine,
                    None,
                    Some(test_normal_routine),
                    ApcMode::KernelMode,
                    iteration as usize, // context
                );
                if TEST_APCS[0].queue(100, 200) {
                    crate::serial_println!("[APC-Test] Queued normal kernel APC");
                }

                // Queue a special kernel APC (no normal routine)
                TEST_APCS[1].init_special(
                    current_thread,
                    test_special_kernel_routine,
                    None,
                );
                if TEST_APCS[1].queue(iteration as usize, 0) {
                    crate::serial_println!("[APC-Test] Queued special kernel APC");
                }
            }
        }

        // Report APC stats every 5 seconds
        if iteration.is_multiple_of(500) {
            let count = unsafe { APC_DELIVERY_COUNT };
            crate::serial_println!("[APC-Test] Stats: iteration={}, APCs delivered={}", iteration, count);
        }

        // Small delay
        for _ in 0..10000 {
            core::hint::spin_loop();
        }
    }
}

// ============================================================================
// Multi-Object Wait Test - WaitForMultipleObjects Demonstration
// ============================================================================

/// Test events for wait testing
static mut WAIT_EVENT1: KEvent = KEvent::new();
static mut WAIT_EVENT2: KEvent = KEvent::new();
static mut WAIT_EVENT3: KEvent = KEvent::new();

/// Test semaphore for wait testing
static mut WAIT_SEMAPHORE: KSemaphore = KSemaphore::new();

/// Wait test counters
static mut WAIT_ANY_COUNT: u32 = 0;
static mut WAIT_ALL_COUNT: u32 = 0;
static mut WAIT_TIMEOUT_COUNT: u32 = 0;

/// Initialize the multi-object wait test
unsafe fn init_wait_test() {
    // Zero and init the events
    let zero_struct = |ptr: *mut u8, size: usize| {
        for i in 0..size {
            core::ptr::write_volatile(ptr.add(i), 0);
        }
    };

    zero_struct(&WAIT_EVENT1 as *const _ as *mut u8, core::mem::size_of::<KEvent>());
    zero_struct(&WAIT_EVENT2 as *const _ as *mut u8, core::mem::size_of::<KEvent>());
    zero_struct(&WAIT_EVENT3 as *const _ as *mut u8, core::mem::size_of::<KEvent>());
    zero_struct(&WAIT_SEMAPHORE as *const _ as *mut u8, core::mem::size_of::<KSemaphore>());

    // Initialize events as auto-reset (synchronization)
    let event1 = &mut WAIT_EVENT1 as *mut KEvent;
    let event2 = &mut WAIT_EVENT2 as *mut KEvent;
    let event3 = &mut WAIT_EVENT3 as *mut KEvent;
    let sem = &mut WAIT_SEMAPHORE as *mut KSemaphore;

    // Use Notification events that stay signaled for testing
    (*event1).init(EventType::Notification, false);
    (*event2).init(EventType::Notification, false);
    (*event3).init(EventType::Notification, false);
    (*sem).init(0, 10);

    WAIT_ANY_COUNT = 0;
    WAIT_ALL_COUNT = 0;
    WAIT_TIMEOUT_COUNT = 0;

    crate::serial_println!("[WAIT] Multi-object wait test initialized");
}

/// Thread that waits on multiple objects using WaitAny
fn wait_any_thread() {
    let thread_id = unsafe {
        let prcb = super::prcb::get_current_prcb();
        (*prcb.current_thread).thread_id
    };

    crate::serial_println!("[WaitAny-{}] Started - waiting for any of 2 events", thread_id);

    loop {
        let start_ticks = apic::get_tick_count();

        // Build array of objects to wait on
        let objects: [*mut DispatcherHeader; 2] = unsafe {[
            &WAIT_EVENT1.header as *const _ as *mut DispatcherHeader,
            &WAIT_EVENT2.header as *const _ as *mut DispatcherHeader,
        ]};

        // Wait for any object
        let status = unsafe {
            wait::ke_wait_for_multiple_objects(&objects, WaitType::WaitAny, Some(2000))
        };

        let elapsed = apic::get_tick_count() - start_ticks;

        match status {
            WaitStatus::Object0 => {
                unsafe { WAIT_ANY_COUNT += 1; }
                crate::serial_println!("[WaitAny-{}] Event1 signaled! elapsed={}ms, count={}",
                    thread_id, elapsed, unsafe { WAIT_ANY_COUNT });
            }
            WaitStatus::Timeout => {
                unsafe { WAIT_TIMEOUT_COUNT += 1; }
                crate::serial_println!("[WaitAny-{}] Timeout after {}ms, timeouts={}",
                    thread_id, elapsed, unsafe { WAIT_TIMEOUT_COUNT });
            }
            s => {
                let val = s as i32;
                if (0..64).contains(&val) {
                    unsafe { WAIT_ANY_COUNT += 1; }
                    crate::serial_println!("[WaitAny-{}] Object {} signaled! elapsed={}ms",
                        thread_id, val, elapsed);
                } else {
                    crate::serial_println!("[WaitAny-{}] Unexpected status: {:?}", thread_id, status);
                }
            }
        }

        // Small delay before next wait
        for _ in 0..50000 {
            core::hint::spin_loop();
        }
    }
}

/// Thread that waits on all objects (WaitAll)
fn wait_all_thread() {
    let thread_id = unsafe {
        let prcb = super::prcb::get_current_prcb();
        (*prcb.current_thread).thread_id
    };

    crate::serial_println!("[WaitAll-{}] Started - waiting for ALL of 2 events", thread_id);

    loop {
        let start_ticks = apic::get_tick_count();

        // Build array of objects to wait on
        let objects: [*mut DispatcherHeader; 2] = unsafe {[
            &WAIT_EVENT1.header as *const _ as *mut DispatcherHeader,
            &WAIT_EVENT3.header as *const _ as *mut DispatcherHeader,
        ]};

        // Wait for all objects (note: using notification event3 which stays signaled)
        let status = unsafe {
            wait::ke_wait_for_multiple_objects(&objects, WaitType::WaitAll, Some(3000))
        };

        let elapsed = apic::get_tick_count() - start_ticks;

        match status {
            WaitStatus::Object0 => {
                unsafe { WAIT_ALL_COUNT += 1; }
                crate::serial_println!("[WaitAll-{}] All objects signaled! elapsed={}ms, count={}",
                    thread_id, elapsed, unsafe { WAIT_ALL_COUNT });
            }
            WaitStatus::Timeout => {
                crate::serial_println!("[WaitAll-{}] Timeout after {}ms", thread_id, elapsed);
            }
            _ => {
                crate::serial_println!("[WaitAll-{}] Unexpected status: {:?}", thread_id, status);
            }
        }

        // Small delay before next wait
        for _ in 0..100000 {
            core::hint::spin_loop();
        }
    }
}

/// Thread that signals events to wake up the wait threads
fn signal_thread() {
    let thread_id = unsafe {
        let prcb = super::prcb::get_current_prcb();
        (*prcb.current_thread).thread_id
    };

    crate::serial_println!("[Signal-{}] Started - signaling events periodically", thread_id);

    let mut iteration = 0u32;

    loop {
        iteration += 1;
        let ticks = apic::get_tick_count();

        // Signal Event1 every 1.5 seconds
        if iteration.is_multiple_of(150) {
            unsafe {
                WAIT_EVENT1.set();
            }
            crate::serial_println!("[Signal] Event1 SET at ticks={}", ticks);
        }

        // Signal Event2 every 2.5 seconds
        if iteration.is_multiple_of(250) {
            unsafe {
                WAIT_EVENT2.set();
            }
            crate::serial_println!("[Signal] Event2 SET at ticks={}", ticks);
        }

        // Signal Event3 (notification, stays signaled) every 3 seconds
        if iteration.is_multiple_of(300) {
            unsafe {
                WAIT_EVENT3.set();
            }
            crate::serial_println!("[Signal] Event3 SET (notification) at ticks={}", ticks);
        }

        // Reset Event3 every 4 seconds
        if iteration.is_multiple_of(400) {
            unsafe {
                WAIT_EVENT3.reset();
            }
            crate::serial_println!("[Signal] Event3 RESET at ticks={}", ticks);
        }

        // Release semaphore every 2 seconds
        if iteration.is_multiple_of(200) {
            unsafe {
                WAIT_SEMAPHORE.release(1);
            }
            crate::serial_println!("[Signal] Semaphore released at ticks={}", ticks);
        }

        // 10ms delay per iteration
        for _ in 0..10000 {
            core::hint::spin_loop();
        }
    }
}

/// Thread that tests single object wait with timeout
fn wait_single_thread() {
    let thread_id = unsafe {
        let prcb = super::prcb::get_current_prcb();
        (*prcb.current_thread).thread_id
    };

    crate::serial_println!("[WaitSingle-{}] Started - testing single object wait", thread_id);

    loop {
        let start_ticks = apic::get_tick_count();

        // Wait for the semaphore
        let sem_header = unsafe {
            &WAIT_SEMAPHORE.header as *const _ as *mut DispatcherHeader
        };

        let status = unsafe {
            wait::ke_wait_for_single_object(sem_header, Some(1500))
        };

        let elapsed = apic::get_tick_count() - start_ticks;

        match status {
            WaitStatus::Object0 => {
                crate::serial_println!("[WaitSingle-{}] Semaphore acquired! elapsed={}ms",
                    thread_id, elapsed);
            }
            WaitStatus::Timeout => {
                crate::serial_println!("[WaitSingle-{}] Timeout after {}ms", thread_id, elapsed);
            }
            _ => {
                crate::serial_println!("[WaitSingle-{}] Status: {:?}", thread_id, status);
            }
        }

        // Small delay before next wait
        for _ in 0..20000 {
            core::hint::spin_loop();
        }
    }
}

/// Monitor thread for wait test statistics
fn wait_monitor_thread() {
    crate::serial_println!("[WaitMonitor] Started - tracking wait statistics");

    let mut last_report = 0u64;

    loop {
        let ticks = apic::get_tick_count();

        // Report every 5 seconds
        if ticks >= last_report + 5000 {
            let (any, all, timeouts) = unsafe {
                (WAIT_ANY_COUNT, WAIT_ALL_COUNT, WAIT_TIMEOUT_COUNT)
            };

            crate::serial_println!("[WaitMonitor] ====================");
            crate::serial_println!("[WaitMonitor] ticks={}", ticks);
            crate::serial_println!("[WaitMonitor]   WaitAny satisfied: {}", any);
            crate::serial_println!("[WaitMonitor]   WaitAll satisfied: {}", all);
            crate::serial_println!("[WaitMonitor]   Timeouts: {}", timeouts);
            crate::serial_println!("[WaitMonitor] ====================");

            last_report = ticks;
        }

        // Small delay
        for _ in 0..10000 {
            core::hint::spin_loop();
        }
    }
}

/// Create threads for multi-object wait testing
///
/// # Safety
/// Must be called after init()
pub unsafe fn create_wait_test_threads() {
    crate::serial_println!("[KE] Creating multi-object wait test threads...");

    // Initialize the wait test resources
    init_wait_test();

    // Create the signal thread (signals events)
    if create_thread(10, signal_thread).is_some() {
        crate::serial_println!("[KE] Signal thread created");
    }

    // Create WaitAny thread
    if create_thread(8, wait_any_thread).is_some() {
        crate::serial_println!("[KE] WaitAny thread created");
    }

    // Create WaitAll thread
    if create_thread(8, wait_all_thread).is_some() {
        crate::serial_println!("[KE] WaitAll thread created");
    }

    // Create single object wait thread
    if create_thread(8, wait_single_thread).is_some() {
        crate::serial_println!("[KE] WaitSingle thread created");
    }

    // Create monitor thread
    if create_thread(6, wait_monitor_thread).is_some() {
        crate::serial_println!("[KE] Wait monitor thread created");
    }

    crate::serial_println!("[KE] Multi-object wait test threads created");
}
