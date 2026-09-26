//! The seccomp recorder. The command's process installs a filter before
//! `exec` that hands the file system calls to the recording process and
//! lets every other call run untouched; its descendants inherit the
//! filter. A supervisor thread per command receives each handed-over call,
//! notes its paths, and lets the kernel run it as made. One thread, because
//! a second one blocked in `SECCOMP_IOCTL_NOTIF_RECV` would not see the
//! hang-up that ends the first.

mod filter;
mod handoff;
mod notify;
mod process;
mod syscalls;

use crate::{FileAccesses, PathState, Unsupported};
use filter::{Filter, NATIVE_AUDIT_ARCH};
use notify::{Listener, Notification, Sizes, Wait};
use process::Process;
use std::{
    io, mem,
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::process::CommandExt,
    },
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};
use syscalls::Effect;

pub const IS_SUPPORTED: bool = true;

/// Letting a notified call continue arrived in Linux 5.5, and the hang-up
/// that tells a supervisor its processes are gone in 5.8.
const MINIMUM_KERNEL: (u32, u32) = (5, 8);

pub struct Recorder {
    shared: Arc<Shared>,
    filter: Arc<Filter>,
    sizes: Sizes,
}

pub struct Prepared {
    _child_end: OwnedFd,
}

struct Shared {
    accesses: Mutex<FileAccesses>,
    /// Set when something ran unrecorded or a call could not be decoded.
    incomplete: AtomicBool,
    finished: AtomicBool,
}

impl Recorder {
    pub fn new() -> Result<Self, Unsupported> {
        if !kernel_is_at_least(MINIMUM_KERNEL) {
            return Err(Unsupported("recording file accesses needs Linux 5.8 or later"));
        }
        let sizes = Sizes::query()
            .map_err(|_| Unsupported("this system does not allow seccomp user notifications"))?;
        Ok(Recorder {
            shared: Arc::new(Shared {
                accesses: Mutex::new(FileAccesses::default()),
                incomplete: AtomicBool::new(false),
                finished: AtomicBool::new(false),
            }),
            filter: Arc::new(Filter::new(
                &syscalls::notified_syscalls(),
                &syscalls::DESCRIPTOR_STATS,
            )),
            sizes,
        })
    }

    pub fn prepare(&self, command: &mut Command) -> io::Result<Prepared> {
        let (parent_end, child_end) = handoff::socket_pair()?;
        let shared = Arc::clone(&self.shared);
        let sizes = self.sizes;
        thread::Builder::new()
            .name("pnpm-fs-recorder".to_string())
            .spawn(move || supervise(&parent_end, &shared, sizes))?;
        let filter = Arc::clone(&self.filter);
        let socket = child_end.as_raw_fd();
        // SAFETY: the closure runs between `fork` and `exec` and only makes
        // system calls: `prctl`, `seccomp`, `sendmsg`, and `close`.
        unsafe {
            command.pre_exec(move || {
                install_and_hand_over(&filter, socket);
                Ok(())
            });
        }
        Ok(Prepared { _child_end: child_end })
    }

    pub fn finish(self) -> Option<FileAccesses> {
        let mut accesses = self.shared.accesses.lock().expect("the record lock is not poisoned");
        self.shared.finished.store(true, Ordering::SeqCst);
        let accesses = mem::take(&mut *accesses);
        (!self.shared.incomplete.load(Ordering::SeqCst)).then_some(accesses)
    }
}

/// Install the filter with a listener and send the listener to the
/// recorder, or report that it could not be installed. Without the filter
/// the command still runs, and the recorder marks the record incomplete.
fn install_and_hand_over(filter: &Filter, socket: i32) {
    let program = filter.program();
    // SAFETY: `prctl` takes no pointers, and `seccomp` reads `program` and
    // the instructions it points at, which live across the call.
    let listener = unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
                &raw const program,
            ) as i32
        } else {
            -1
        }
    };
    handoff::send(socket, listener);
    if listener >= 0 {
        // SAFETY: the listener was created above and is not used again in
        // this process.
        unsafe {
            libc::close(listener);
        }
    }
}

/// Receive the listener of one prepared command and serve it until every
/// process it filters is gone.
fn supervise(socket: &OwnedFd, shared: &Arc<Shared>, sizes: Sizes) {
    let Ok(Some(fd)) = handoff::receive(socket) else {
        shared.mark_incomplete();
        return;
    };
    let listener = Listener::new(fd, sizes);
    listener.prefer_synchronous_wake_up();
    serve(listener, shared);
}

fn serve(mut listener: Listener, shared: &Shared) {
    loop {
        match listener.wait() {
            Ok(Wait::Ready) => {}
            Ok(Wait::HungUp) => return,
            Err(_) => break,
        }
        match listener.receive() {
            Ok(Some(notification)) => {
                shared.handle(&notification, &listener);
                listener.resume(notification.id);
            }
            Ok(None) => {}
            Err(_) => break,
        }
    }
    shared.mark_incomplete();
}

impl Shared {
    fn handle(&self, notification: &Notification, listener: &Listener) {
        if self.finished.load(Ordering::Relaxed) {
            return;
        }
        let decoded = (notification.arch == NATIVE_AUDIT_ARCH).then(|| {
            let process = Process { tid: notification.tid };
            syscalls::effect(process, notification.number, &notification.args)
        });
        match decoded {
            Some(Ok(Some(effect))) => self.record(effect),
            Some(Ok(None)) => {}
            // A thread that died while its call waited leaves nothing to
            // decode and nothing to miss.
            _ if !listener.is_pending(notification.id) => {}
            _ => self.mark_incomplete(),
        }
    }

    fn record(&self, effect: Effect) {
        let mut accesses = self.accesses.lock().expect("the record lock is not poisoned");
        if self.finished.load(Ordering::Relaxed) {
            return;
        }
        match effect {
            Effect::Read(path) => {
                let path = observe(&mut accesses, &path);
                accesses.reads.insert(path);
            }
            Effect::Probe(path) => {
                let path = observe(&mut accesses, &path);
                accesses.probes.insert(path);
            }
            Effect::List(path) => {
                let path = observe(&mut accesses, &path);
                accesses.listings.insert(path);
            }
            Effect::Write(paths) => {
                for path in paths {
                    note_write(&mut accesses, &path);
                }
            }
            Effect::ReadWrite(path) => {
                let path = observe(&mut accesses, &path);
                accesses.reads.insert(path.clone());
                note_write(&mut accesses, &path);
            }
        }
    }

    fn mark_incomplete(&self) {
        if !self.finished.load(Ordering::SeqCst) {
            self.incomplete.store(true, Ordering::SeqCst);
        }
    }
}

/// Note the state of `path` the first time it is accessed. Runs before the
/// call is let through, so the state is the one the call saw.
fn observe(accesses: &mut FileAccesses, path: &Path) -> PathBuf {
    let path = clean(path);
    if !accesses.observed.contains_key(&path) {
        let state = PathState::of(&path);
        accesses.observed.insert(path.clone(), state);
    }
    path
}

fn note_write(accesses: &mut FileAccesses, path: &Path) {
    let path = clean(path);
    let read_while_present = accesses.reads.contains(&path)
        && accesses.observed.get(&path).is_some_and(PathState::exists);
    if read_while_present && !accesses.writes.contains(&path) {
        accesses.modified_reads.insert(path.clone());
    }
    accesses.writes.insert(path);
}

/// `path` without `.` components, repeated separators, or a trailing one.
fn clean(path: &Path) -> PathBuf {
    path.components().collect()
}

fn kernel_is_at_least(minimum: (u32, u32)) -> bool {
    // SAFETY: an all-zero `utsname` is valid for `uname` to fill in.
    let mut name: libc::utsname = unsafe { mem::zeroed() };
    // SAFETY: `uname` writes into `name`, which lives across the call.
    if unsafe { libc::uname(&raw mut name) } != 0 {
        return false;
    }
    // SAFETY: the kernel NUL-terminates `release`.
    let release = unsafe { std::ffi::CStr::from_ptr(name.release.as_ptr()) };
    release
        .to_str()
        .ok()
        .and_then(parse_release)
        .is_some_and(|version| version >= minimum)
}

/// The major and minor version of a kernel release such as
/// `6.8.0-45-generic`.
fn parse_release(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.split(|character: char| !character.is_ascii_digit());
    Some((parts.next()?.parse().ok()?, parts.next()?.parse().ok()?))
}

#[cfg(test)]
mod tests;
