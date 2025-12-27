//! Kernel Event Implementation (KEVENT)
//!
//! Events are synchronization objects used for signaling between threads.
//! A thread can wait for an event to be signaled, and another thread
//! can signal the event to wake the waiting thread(s).
//!
//! Two types of events:
//! - **Notification (Manual Reset)**: Stays signaled until explicitly reset.
//!   Wakes ALL waiting threads when signaled.
//! - **Synchronization (Auto Reset)**: Automatically resets after waking
//!   ONE thread. Only one waiter is released per signal.
//!
//! # Usage
//! ```
//! static EVENT: KEvent = KEvent::new();
//!
//! // Initialize as notification event, initially not signaled
//! EVENT.init(EventType::Notification, false);
//!
//! // Thread A waits
//! EVENT.wait();
//!
//! // Thread B signals
//! EVENT.set();
//! ```

use super::dispatcher::{DispatcherHeader, DispatcherType, KWaitBlock, WaitType};
use super::thread::{KThread, ThreadState};
use super::prcb::get_current_prcb_mut;
use super::scheduler;
use crate::containing_record;

/// Event type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EventType {
    /// Notification event (manual reset)
    /// - Wakes ALL waiters when signaled
    /// - Stays signaled until explicitly reset
    Notification = 0,
    /// Synchronization event (auto reset)
    /// - Wakes ONE waiter when signaled
    /// - Automatically resets after waking a thread
    Synchronization = 1,
}

/// Kernel Event
///
/// Equivalent to NT's KEVENT
#[repr(C)]
pub struct KEvent {
    /// Dispatcher header (must be first for casting)
    pub header: DispatcherHeader,
    /// Event type (notification or synchronization)
    event_type: EventType,
}

// Safety: KEvent is designed for multi-threaded access
unsafe impl Sync for KEvent {}
unsafe impl Send for KEvent {}

impl KEvent {
    /// Create a new uninitialized event
    pub const fn new() -> Self {
        Self {
            header: DispatcherHeader::new(DispatcherType::Event),
            event_type: EventType::Notification,
        }
    }

    /// Initialize the event
    ///
    /// # Arguments
    /// * `event_type` - Notification (manual reset) or Synchronization (auto reset)
    /// * `initial_state` - true = signaled, false = not signaled
    pub fn init(&mut self, event_type: EventType, initial_state: bool) {
        let signal = if initial_state { 1 } else { 0 };
        self.header.init(DispatcherType::Event, signal);
        self.event_type = event_type;
    }

    /// Get the event type
    #[inline]
    pub fn event_type(&self) -> EventType {
        self.event_type
    }

    /// Check if the event is signaled
    #[inline]
    pub fn is_signaled(&self) -> bool {
        self.header.is_signaled()
    }

    /// Set (signal) the event
    ///
    /// For notification events: wakes all waiters, stays signaled
    /// For synchronization events: wakes one waiter, auto-resets
    ///
    /// Returns the previous signal state
    pub unsafe fn set(&self) -> bool {
        let was_signaled = self.header.signal_state() > 0;

        match self.event_type {
            EventType::Notification => {
                // Set signaled and wake ALL waiters
                self.header.set_signal_state(1);
                self.wake_all_waiters();
            }
            EventType::Synchronization => {
                if !self.header.has_waiters() {
                    // No waiters - just set signaled
                    self.header.set_signal_state(1);
                } else {
                    // Wake one waiter, don't set signaled (auto-reset)
                    self.wake_one_waiter();
                    // signal_state stays 0
                }
            }
        }

        was_signaled
    }

    /// Reset (unsignal) the event
    ///
    /// Returns the previous signal state
    pub unsafe fn reset(&self) -> bool {
        let was_signaled = self.header.signal_state() > 0;
        self.header.set_signal_state(0);
        was_signaled
    }

    /// Pulse the event
    ///
    /// Sets the event, wakes waiters, then immediately resets.
    /// For notification: wakes all current waiters
    /// For synchronization: wakes one waiter
    ///
    /// Returns the previous signal state
    pub unsafe fn pulse(&self) -> bool {
        let was_signaled = self.header.signal_state() > 0;

        match self.event_type {
            EventType::Notification => {
                self.wake_all_waiters();
            }
            EventType::Synchronization => {
                if self.header.has_waiters() {
                    self.wake_one_waiter();
                }
            }
        }

        // Always reset after pulse
        self.header.set_signal_state(0);

        was_signaled
    }

    /// Wait for the event to be signaled
    ///
    /// Blocks the calling thread until the event is signaled.
    /// For auto-reset events, the event is reset after this returns.
    ///
    /// # Safety
    /// Must be called from thread context (not interrupt)
    pub unsafe fn wait(&self) {
        let prcb = get_current_prcb_mut();
        let current = prcb.current_thread;

        // Check if already signaled
        if self.header.signal_state() > 0 {
            // Signaled - consume based on type
            if self.event_type == EventType::Synchronization {
                self.header.set_signal_state(0);
            }
            return;
        }

        // Not signaled - must wait
        self.wait_for_signal(current);

        // When we wake up, for sync events the signal was consumed
        // For notification events it might still be signaled
    }

    /// Wait with timeout
    ///
    /// Returns true if the event was signaled, false if timed out.
    /// Timeout is in scheduler ticks.
    ///
    /// # Note
    /// Timeout not yet fully implemented - currently waits indefinitely
    pub unsafe fn wait_timeout(&self, _timeout_ticks: u64) -> bool {
        // TODO: Implement timeout using timer
        self.wait();
        true
    }

    /// Try to wait without blocking
    ///
    /// Returns true if the event was signaled, false otherwise
    pub unsafe fn try_wait(&self) -> bool {
        if self.header.signal_state() > 0 {
            if self.event_type == EventType::Synchronization {
                self.header.set_signal_state(0);
            }
            true
        } else {
            false
        }
    }

    /// Internal: wait for signal
    unsafe fn wait_for_signal(&self, thread: *mut KThread) {
        // Create wait block on stack
        let mut wait_block = KWaitBlock::new();
        wait_block.init(
            thread,
            &self.header as *const _ as *mut DispatcherHeader,
            WaitType::WaitAny,
        );

        // Add to event's wait list
        self.header.wait_list().insert_tail(&mut wait_block.wait_list_entry);

        // Set thread state to waiting
        (*thread).state = ThreadState::Waiting;

        // Yield to scheduler
        scheduler::ki_dispatch_interrupt();

        // When we return, we've been woken up
    }

    /// Internal: wake one waiter
    unsafe fn wake_one_waiter(&self) {
        if !self.header.has_waiters() {
            return;
        }

        // Remove first waiter
        let entry = self.header.wait_list().remove_head();
        let wait_block = containing_record!(entry, KWaitBlock, wait_list_entry);
        let thread = (*wait_block).thread;

        // Make thread ready
        (*thread).state = ThreadState::Ready;
        scheduler::ki_ready_thread(thread);
    }

    /// Internal: wake all waiters
    unsafe fn wake_all_waiters(&self) {
        while self.header.has_waiters() {
            let entry = self.header.wait_list().remove_head();
            let wait_block = containing_record!(entry, KWaitBlock, wait_list_entry);
            let thread = (*wait_block).thread;

            (*thread).state = ThreadState::Ready;
            scheduler::ki_ready_thread(thread);
        }
    }
}

impl Default for KEvent {
    fn default() -> Self {
        Self::new()
    }
}
