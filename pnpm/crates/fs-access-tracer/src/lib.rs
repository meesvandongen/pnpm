//! Record the files a process tree touches while it runs: which files it
//! reads, which paths it probes (including ones that do not exist), which
//! directories it lists, and which paths it writes.
//!
//! `pnpm pipeline` uses the record as a task's automatically tracked cache
//! inputs and outputs. The tracer follows every descendant of the traced
//! command, so a script that spawns `node`, which spawns a compiler, is
//! recorded as one task.
//!
//! Tracing is implemented for Linux on x86-64 and 64-bit Arm, where it uses
//! `ptrace` with a seccomp filter that stops the tracee only at the file
//! system system calls the record needs. [`IS_SUPPORTED`] is `false`
//! elsewhere, and [`trace_command`] reports an incomplete trace.
//!
//! A tracer must be the process that waits for every tracee, which a
//! multi-threaded host cannot promise. The [`helper`] module therefore runs
//! the tracer in a process of its own, launched through
//! [`helper::launcher`] and entered through [`helper::try_run`].

pub mod helper;

pub use accesses::FileAccesses;

mod accesses;

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
mod linux;
#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
use linux as platform;

#[cfg(not(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64"))))]
mod unsupported;
#[cfg(not(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64"))))]
use unsupported as platform;

use std::{
    io,
    process::{Command, ExitStatus},
};

/// Whether this build of pnpm can trace file accesses at all. A supported
/// platform can still refuse at run time (a sandbox that forbids `ptrace`,
/// a kernel without `PTRACE_GET_SYSCALL_INFO`); [`Trace::complete`] says
/// whether it did.
pub const IS_SUPPORTED: bool = platform::IS_SUPPORTED;

/// The outcome of [`trace_command`].
#[derive(Debug)]
pub struct Trace {
    pub status: ExitStatus,
    pub accesses: FileAccesses,
    /// `false` when some of the process tree ran untraced, so
    /// [`Trace::accesses`] may be missing paths the command touched.
    pub complete: bool,
}

/// Run `command` to completion and record the files it and its
/// descendants accessed.
///
/// The command's stdio, environment, and working directory are used as
/// configured. Descendants that outlive the command are released from the
/// trace when it exits, and their later accesses are not recorded.
pub fn trace_command(command: Command) -> io::Result<Trace> {
    platform::trace_command(command)
}
