//! Record the files a process tree touches while it runs: which files it
//! reads, which paths it probes (including ones that do not exist), which
//! directories it lists, which programs it executes, and which paths it
//! writes.
//!
//! `pnpm pipeline` uses the record as a task's automatically tracked cache
//! inputs and outputs. A [`Recorder`] follows every descendant of the
//! commands it prepares, so a script that spawns `node`, which spawns a
//! compiler, is recorded as one task.
//!
//! How it records depends on the platform:
//!
//! - Linux 5.8 and later (x86-64, 64-bit Arm): a seccomp filter hands each
//!   file system call to a supervisor thread in the recording process,
//!   which notes the call's paths and lets the kernel run it.
//! - macOS and Windows: a hook library loaded into every process of the
//!   tree (`pnpm-fs-access-hook`) logs the accesses from inside, and pnpm
//!   reads the logs back (see `pnpm-fs-access-protocol`).
//!
//! [`IS_SUPPORTED`] is `false` on every other platform.

pub use accesses::FileAccesses;
pub use pnpm_fs_access_protocol::PathState;

mod accesses;
#[cfg(any(target_os = "macos", windows, test))]
mod log;

#[cfg(any(windows, target_os = "macos"))]
mod artifact;

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
mod linux;
#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
use linux as platform;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as platform;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as platform;

#[cfg(not(any(
    all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")),
    windows,
    target_os = "macos",
)))]
mod unsupported;
#[cfg(not(any(
    all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")),
    windows,
    target_os = "macos",
)))]
use unsupported as platform;

use std::{
    ffi::OsStr,
    fmt, io,
    path::PathBuf,
    process::{Child, Command},
};

/// Whether this build of pnpm can record file accesses at all. A supported
/// build can still find the running system unable to, which
/// [`Recorder::new`] reports.
pub const IS_SUPPORTED: bool = platform::IS_SUPPORTED;

/// Why [`Recorder::new`] cannot record on this system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unsupported(&'static str);

impl fmt::Display for Unsupported {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for Unsupported {}

/// Why [`Recorder::finish`] cannot vouch for every access of the record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unobserved {
    /// A program of the tree ran without the recorder following it, such
    /// as a macOS system program. The path is empty when the program is
    /// not known.
    Program(PathBuf),
    /// A process made a file system call the recorder could not follow.
    Call,
    /// A process's log of its accesses could not be read whole.
    Log,
    /// The recorder could not attach to the command.
    Attach,
}

impl fmt::Display for Unobserved {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Unobserved::Program(path) if path.as_os_str().is_empty() => {
                formatter.write_str("a program ran without the recorder")
            }
            Unobserved::Program(path) => {
                write!(formatter, "{} ran without the recorder", path.display())
            }
            Unobserved::Call => formatter.write_str(
                "a process made a file system call the recorder could not follow",
            ),
            Unobserved::Log => formatter.write_str("the log of a process's accesses was cut short"),
            Unobserved::Attach => {
                formatter.write_str("the recorder could not attach to the command")
            }
        }
    }
}

impl std::error::Error for Unobserved {}

/// Records the file accesses of the commands [`Recorder::prepare`] sets
/// up, and of every process they start, until [`Recorder::finish`].
pub struct Recorder(platform::Recorder);

/// Returned by [`Recorder::prepare`]. Hand it the process once the command
/// has spawned, with [`Prepared::started`]; drop it when the command
/// failed to spawn.
#[must_use = "a prepared command's process must be reported with `started`"]
pub struct Prepared(platform::Prepared);

impl Recorder {
    pub fn new() -> Result<Self, Unsupported> {
        platform::Recorder::new().map(Recorder)
    }

    /// A command that runs `program`. Where the platform keeps its own
    /// programs from being recorded (the system shell on macOS), a
    /// recordable equivalent runs instead.
    #[must_use]
    pub fn command(&self, program: &OsStr) -> Command {
        self.0.command(program)
    }

    /// Set `command` up so that the process it spawns, and every process
    /// that one starts, is recorded.
    pub fn prepare(&self, command: &mut Command) -> io::Result<Prepared> {
        self.0.prepare(command).map(Prepared)
    }

    /// Stop recording and return what was recorded, or why some of it
    /// could not be observed.
    ///
    /// Processes a prepared command left running keep running, but what
    /// they access from now on is not recorded.
    pub fn finish(self) -> Result<FileAccesses, Unobserved> {
        self.0.finish()
    }
}

impl Prepared {
    /// Report the process the prepared command spawned. Call it right
    /// after the spawn: on Windows the process waits, suspended, until
    /// then.
    pub fn started(self, child: &Child) {
        self.0.started(child);
    }
}
