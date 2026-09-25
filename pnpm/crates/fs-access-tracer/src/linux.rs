//! The `ptrace` tracer. The command's process stops itself for tracing
//! with `PTRACE_TRACEME` and installs a seccomp filter before `exec`, so
//! every descendant runs under both. The filter hands the file system
//! system calls to the tracer and lets every other call run without a
//! stop; the tracer records the call's paths and resumes it, following a
//! write only to its exit to learn whether it succeeded.

mod forwarding;
mod seccomp;
mod syscalls;
mod tracee;

use crate::{FileAccesses, Trace};
use libc::{c_int, c_void, pid_t};
use seccomp::{Filter, NATIVE_AUDIT_ARCH};
use std::{
    collections::{HashMap, HashSet},
    io,
    os::unix::process::{CommandExt, ExitStatusExt},
    path::PathBuf,
    process::{Command, ExitStatus},
};
use syscalls::Effect;
use tracee::{SyscallStop, Tracee};

pub const IS_SUPPORTED: bool = true;

/// What the command's process reports, before `exec`, about how far its
/// tracing setup got.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Setup {
    Untraced = b'u',
    Unfiltered = b't',
    Filtered = b'f',
}

pub fn trace_command(mut command: Command) -> io::Result<Trace> {
    let filter = Filter::new(&syscalls::traced_syscalls());
    let setup_pipe = SetupPipe::new()?;
    let report = setup_pipe.write;
    // SAFETY: the closure runs between `fork` and `exec` and only makes
    // system calls: `ptrace`, `prctl`, and `write`.
    unsafe {
        command.pre_exec(move || {
            report_setup(report, set_up_tracee(&filter));
            Ok(())
        });
    }
    let _forwarding = forwarding::install();
    let spawned = command.spawn();
    let setup = setup_pipe.read_setup();
    let child = spawned?;
    let root = pid_t::try_from(child.id()).map_err(io::Error::other)?;
    forwarding::set_target(root);
    Tracer::new(root, setup == Setup::Filtered).run()
}

fn set_up_tracee(filter: &Filter) -> Setup {
    // SAFETY: `PTRACE_TRACEME` takes no pointers.
    let traced = unsafe {
        libc::ptrace(
            libc::PTRACE_TRACEME as _,
            0,
            std::ptr::null_mut::<c_void>(),
            std::ptr::null_mut::<c_void>(),
        )
    } == 0;
    // Without a tracer the filter would fail every call it traps, so it
    // is only installed on a traced process.
    match (traced, traced && filter.install()) {
        (false, _) => Setup::Untraced,
        (true, false) => Setup::Unfiltered,
        (true, true) => Setup::Filtered,
    }
}

fn report_setup(fd: c_int, setup: Setup) {
    let byte = setup as u8;
    // SAFETY: writes one byte from a live local.
    unsafe {
        libc::write(fd, (&raw const byte).cast(), 1);
    }
}

/// A close-on-exec pipe the command's process reports its [`Setup`]
/// through before `exec` closes the write end.
struct SetupPipe {
    read: c_int,
    write: c_int,
}

impl SetupPipe {
    fn new() -> io::Result<Self> {
        let mut fds = [0 as c_int; 2];
        // SAFETY: `pipe2` writes two descriptors into `fds`.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(SetupPipe { read: fds[0], write: fds[1] })
    }

    fn read_setup(self) -> Setup {
        let mut byte = Setup::Untraced as u8;
        // SAFETY: the descriptors are this pipe's own and closed once. The
        // write end is closed first, so a child that never reported leaves
        // `read` at end of file instead of blocking.
        unsafe {
            libc::close(self.write);
            libc::read(self.read, (&raw mut byte).cast(), 1);
            libc::close(self.read);
        }
        match byte {
            b'f' => Setup::Filtered,
            b't' => Setup::Unfiltered,
            _ => Setup::Untraced,
        }
    }
}

/// How to restart a stopped tracee.
enum Resume {
    Continue(c_int),
    ToSyscallExit,
    Kill,
}

struct Tracer {
    root: pid_t,
    root_status: Option<c_int>,
    accesses: FileAccesses,
    /// Paths of write calls waiting for their exit, per thread.
    pending_writes: HashMap<pid_t, Vec<PathBuf>>,
    /// Threads that have stopped at least once.
    attached: HashSet<pid_t>,
    complete: bool,
}

impl Tracer {
    fn new(root: pid_t, filtered: bool) -> Self {
        Tracer {
            root,
            root_status: None,
            accesses: FileAccesses::default(),
            pending_writes: HashMap::new(),
            attached: HashSet::new(),
            complete: filtered,
        }
    }

    fn run(mut self) -> io::Result<Trace> {
        while let Some((tid, status)) = wait_any()? {
            self.handle(tid, status);
        }
        let status =
            self.root_status.ok_or_else(|| io::Error::other("lost track of the traced command"))?;
        Ok(Trace {
            status: ExitStatus::from_raw(status),
            accesses: self.accesses,
            complete: self.complete,
        })
    }

    fn handle(&mut self, tid: pid_t, status: c_int) {
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            self.on_exit(tid, status);
            return;
        }
        if !libc::WIFSTOPPED(status) {
            return;
        }
        let resume =
            if self.root_status.is_some() { Resume::Kill } else { self.on_stop(tid, status) };
        // A thread still owing a write's exit is kept on the way to it,
        // whatever stopped it in between.
        let awaiting_exit = self.pending_writes.contains_key(&tid);
        restart(tid, &resume, awaiting_exit);
    }

    /// Once the command exits, what it left running is killed: the trace
    /// cannot outlive the task it belongs to.
    fn on_exit(&mut self, tid: pid_t, status: c_int) {
        self.pending_writes.remove(&tid);
        self.attached.remove(&tid);
        if tid != self.root {
            return;
        }
        self.root_status = Some(status);
        forwarding::set_target(0);
        for leftover in &self.attached {
            kill_thread(*leftover);
        }
    }

    fn on_stop(&mut self, tid: pid_t, status: c_int) -> Resume {
        let signal = libc::WSTOPSIG(status);
        let event = status >> 16;
        if self.attached.insert(tid) {
            return self.on_first_stop(tid, signal);
        }
        match (signal, event) {
            (libc::SIGTRAP, libc::PTRACE_EVENT_SECCOMP) => self.on_syscall_entry(Tracee { tid }),
            (sig, _) if sig == libc::SIGTRAP | 0x80 => {
                self.on_syscall_exit(Tracee { tid });
                Resume::Continue(0)
            }
            (libc::SIGTRAP, libc::PTRACE_EVENT_EXEC) => {
                self.record_executable(Tracee { tid });
                Resume::Continue(0)
            }
            (libc::SIGTRAP, event) if event != 0 => Resume::Continue(0),
            (signal, _) if is_group_stop(tid, signal) => Resume::Continue(0),
            (signal, _) => Resume::Continue(signal),
        }
    }

    /// The command's first stop is the trap after its `exec`, which is
    /// when the tracer can set its options. A descendant's first stop is
    /// the `SIGSTOP` of its automatic attachment.
    fn on_first_stop(&mut self, tid: pid_t, signal: c_int) -> Resume {
        if tid != self.root {
            return Resume::Continue(if signal == libc::SIGSTOP { 0 } else { signal });
        }
        if set_options(tid).is_err() {
            self.complete = false;
        }
        self.record_executable(Tracee { tid });
        Resume::Continue(0)
    }

    fn on_syscall_entry(&mut self, tracee: Tracee) -> Resume {
        let Some(SyscallStop::Entry { arch, number, args }) = tracee.syscall_stop() else {
            self.complete = false;
            return Resume::Continue(0);
        };
        if arch != NATIVE_AUDIT_ARCH {
            self.complete = false;
            return Resume::Continue(0);
        }
        match syscalls::effect(tracee, number, &args) {
            Ok(Some(Effect::Read(path))) => self.accesses.reads.insert(path),
            Ok(Some(Effect::Probe(path))) => self.accesses.probes.insert(path),
            Ok(Some(Effect::List(path))) => self.accesses.listings.insert(path),
            Ok(Some(Effect::Write(paths))) => {
                self.pending_writes.insert(tracee.tid, paths);
                return Resume::ToSyscallExit;
            }
            Ok(None) => false,
            Err(()) => {
                self.complete = false;
                false
            }
        };
        Resume::Continue(0)
    }

    fn on_syscall_exit(&mut self, tracee: Tracee) {
        let Some(paths) = self.pending_writes.remove(&tracee.tid) else { return };
        match tracee.syscall_stop() {
            Some(SyscallStop::Exit { failed: false }) => self.accesses.writes.extend(paths),
            Some(SyscallStop::Exit { failed: true }) => {}
            _ => self.complete = false,
        }
    }

    fn record_executable(&mut self, tracee: Tracee) {
        if let Some(executable) = tracee.executable() {
            self.accesses.reads.insert(executable);
        }
    }
}

/// The next status change of any tracee, or `None` once none are left.
fn wait_any() -> io::Result<Option<(pid_t, c_int)>> {
    loop {
        let mut status = 0;
        // `__WNOTHREAD` leaves other threads' children, traced or not, to
        // the threads that wait for them.
        // SAFETY: `waitpid` writes the status into a live local.
        let tid = unsafe { libc::waitpid(-1, &raw mut status, libc::__WALL | libc::__WNOTHREAD) };
        if tid >= 0 {
            return Ok(Some((tid, status)));
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EINTR) => forwarding::forward_pending(),
            Some(libc::ECHILD) => return Ok(None),
            _ => return Err(error),
        }
    }
}

fn set_options(tid: pid_t) -> io::Result<()> {
    let options = libc::PTRACE_O_TRACESYSGOOD
        | libc::PTRACE_O_TRACEFORK
        | libc::PTRACE_O_TRACEVFORK
        | libc::PTRACE_O_TRACECLONE
        | libc::PTRACE_O_TRACEEXEC
        | libc::PTRACE_O_TRACESECCOMP
        | libc::PTRACE_O_EXITKILL;
    // SAFETY: `PTRACE_SETOPTIONS` takes the options as its data word.
    let result = unsafe {
        libc::ptrace(
            libc::PTRACE_SETOPTIONS as _,
            tid,
            std::ptr::null_mut::<c_void>(),
            options as usize as *mut c_void,
        )
    };
    if result == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

/// A stopping signal the tracee has no pending `siginfo` for put the
/// whole process into a group-stop rather than delivering a signal. It is
/// resumed at once: job control inside a traced task is not supported.
fn is_group_stop(tid: pid_t, signal: c_int) -> bool {
    if !matches!(signal, libc::SIGSTOP | libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU) {
        return false;
    }
    let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::uninit();
    // SAFETY: the kernel writes a `siginfo_t` into `info` when it succeeds;
    // the value is only used for the success check.
    let result = unsafe {
        libc::ptrace(
            libc::PTRACE_GETSIGINFO as _,
            tid,
            std::ptr::null_mut::<c_void>(),
            info.as_mut_ptr().cast::<c_void>(),
        )
    };
    result != 0
}

fn restart(tid: pid_t, resume: &Resume, awaiting_exit: bool) {
    let (request, signal) = match resume {
        Resume::Continue(signal) if awaiting_exit => (libc::PTRACE_SYSCALL, *signal),
        Resume::Continue(signal) => (libc::PTRACE_CONT, *signal),
        Resume::ToSyscallExit => (libc::PTRACE_SYSCALL, 0),
        Resume::Kill => {
            kill_thread(tid);
            (libc::PTRACE_CONT, libc::SIGKILL)
        }
    };
    // SAFETY: the restart requests take the signal to deliver as their
    // data word. A tracee killed meanwhile fails with ESRCH, which is fine.
    unsafe {
        libc::ptrace(
            request as _,
            tid,
            std::ptr::null_mut::<c_void>(),
            signal as usize as *mut c_void,
        );
    }
}

fn kill_thread(tid: pid_t) {
    // SAFETY: signals a thread of the traced tree. SIGKILL ends its whole
    // process, and ESRCH for one that is already gone is fine.
    unsafe {
        libc::syscall(libc::SYS_tkill, tid, libc::SIGKILL);
    }
}

#[cfg(test)]
mod tests;
