//! Termination signals the tracing process receives are passed on to the
//! traced command, so a tracer standing between a caller and the command
//! does not swallow a cancellation.

use libc::{c_int, pid_t};
use std::sync::atomic::{AtomicI32, Ordering};

const FORWARDED: [c_int; 4] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];

static TARGET: AtomicI32 = AtomicI32::new(0);
static PENDING: AtomicI32 = AtomicI32::new(0);

/// Restores the handlers [`install`] replaced.
pub(super) struct Installed {
    previous: [libc::sigaction; FORWARDED.len()],
}

/// Catch the forwarded signals. The handler is installed without
/// `SA_RESTART`, so a signal interrupts the tracer's `waitpid`, which then
/// calls [`forward_pending`].
pub(super) fn install() -> Installed {
    // SAFETY: an all-zero `sigaction` is a valid value to be overwritten.
    let mut previous: [libc::sigaction; FORWARDED.len()] = unsafe { std::mem::zeroed() };
    for (signal, previous) in FORWARDED.iter().zip(previous.iter_mut()) {
        // SAFETY: as above; the fields that matter are set before use.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = record_signal as *const () as libc::sighandler_t;
        // SAFETY: both pointers are to live locals, and `record_signal`
        // only touches an atomic, which is async-signal-safe.
        unsafe {
            libc::sigemptyset(&raw mut action.sa_mask);
            libc::sigaction(*signal, &raw const action, previous);
        }
    }
    Installed { previous }
}

impl Drop for Installed {
    fn drop(&mut self) {
        for (signal, previous) in FORWARDED.iter().zip(&self.previous) {
            // SAFETY: restores a handler `sigaction` returned earlier.
            unsafe {
                libc::sigaction(*signal, previous, std::ptr::null_mut());
            }
        }
    }
}

pub(super) fn set_target(pid: pid_t) {
    TARGET.store(pid, Ordering::SeqCst);
}

pub(super) fn forward_pending() {
    let signal = PENDING.swap(0, Ordering::SeqCst);
    let target = TARGET.load(Ordering::SeqCst);
    if signal != 0 && target > 0 {
        // SAFETY: signals the traced command, which the tracer still has
        // to reap, so its pid cannot have been reused.
        unsafe {
            libc::kill(target, signal);
        }
    }
}

extern "C" fn record_signal(signal: c_int) {
    PENDING.store(signal, Ordering::SeqCst);
}
