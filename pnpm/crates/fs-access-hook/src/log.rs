//! This process's access log: records appended to a file of its own in
//! the log directory, each with a single write. A process forked without
//! `exec` keeps writing to its parent's file, under its own pid.

use pnpm_fs_access_protocol::{Access, Event, PathState, Record, encode, max_record_len};
use std::sync::atomic::{AtomicU64, Ordering};

/// Paths longer than this are not logged, and make the record incomplete.
pub(crate) const MAX_PATH_BYTES: usize = 4096 * 2;

use crate::os;
use std::cell::Cell;

thread_local! {
    /// Set while the hook itself runs, so the calls it makes pass through:
    /// the library functions it calls may make interposed or hooked calls
    /// of their own (`getcwd` opening `.`, for one).
    static IN_HOOK: Cell<bool> = const { Cell::new(false) };
}

/// Run `record` unless the current thread is already inside the hook.
pub(crate) fn guarded(record: impl FnOnce()) {
    let entered = IN_HOOK
        .try_with(|busy| !busy.replace(true))
        .unwrap_or(false);
    if entered {
        record();
        let _ = IN_HOOK.try_with(|busy| busy.set(false));
    }
}

/// Append `event` to the log. An event too large to log is replaced by
/// [`Event::Unrecorded`], which tells pnpm the record is incomplete.
pub(crate) fn write(event: Event<'_>) {
    let mut buffer = [0u8; max_record_len(MAX_PATH_BYTES)];
    let record = Record { pid: os::pid(), time: os::now(), event };
    let unrecorded = Record { event: Event::Unrecorded, ..record };
    if let Some(len) = encode(&record, &mut buffer).or_else(|| encode(&unrecorded, &mut buffer)) {
        os::append(&buffer[..len]);
    }
}

/// Log an access unless this process logged the same access to the same
/// path before. `state` is asked for only when the access is logged.
pub(crate) fn access(access: Access, path: &[u8], state: impl FnOnce() -> Option<PathState>) {
    if SEEN.insert(access, path) {
        write(Event::Accessed { access, state: state(), path });
    }
}

/// A fixed-size set of the accesses this process logged, by hash. It takes
/// no locks and allocates nothing, so it is safe between `fork` and `exec`.
/// A full set, or a hash collision, only means an access is logged twice
/// or not at all again; a missed repeat is harmless because the first
/// access of each path is the one the record keeps.
struct Seen {
    slots: [AtomicU64; SEEN_SLOTS],
}

const SEEN_SLOTS: usize = 1 << 16;

static SEEN: Seen = Seen { slots: [const { AtomicU64::new(0) }; SEEN_SLOTS] };

impl Seen {
    /// Add the access, returning whether it was not there yet.
    fn insert(&self, access: Access, path: &[u8]) -> bool {
        let hash = fnv1a(access as u8, path) | 1;
        let start = (hash as usize) & (SEEN_SLOTS - 1);
        for probe in 0..16 {
            let slot = &self.slots[(start + probe) & (SEEN_SLOTS - 1)];
            match slot.compare_exchange(0, hash, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return true,
                Err(existing) if existing == hash => return false,
                Err(_) => {}
            }
        }
        true
    }
}

fn fnv1a(tag: u8, bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in std::iter::once(&tag).chain(bytes) {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}
