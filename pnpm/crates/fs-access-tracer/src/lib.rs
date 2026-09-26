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
//! Recording is implemented for Linux 5.8 and later on x86-64 and 64-bit
//! Arm. A seccomp filter hands each file system call to a supervisor thread
//! in the recording process, which notes the call's paths and lets the
//! kernel run it. [`IS_SUPPORTED`] is `false` on every other platform.

pub use accesses::{FileAccesses, PathState};

mod accesses;

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
mod linux;
#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
use linux as platform;

#[cfg(not(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64"))))]
mod unsupported;
#[cfg(not(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64"))))]
use unsupported as platform;

use std::{fmt, io, process::Command};

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

/// Records the file accesses of the commands [`Recorder::prepare`] sets
/// up, and of every process they start, until [`Recorder::finish`].
pub struct Recorder(platform::Recorder);

/// Returned by [`Recorder::prepare`]; keep it until the command has been
/// spawned (or failed to spawn).
#[must_use = "dropping it before the command is spawned stops the recording"]
pub struct Prepared {
    _held: platform::Prepared,
}

impl Recorder {
    pub fn new() -> Result<Self, Unsupported> {
        platform::Recorder::new().map(Recorder)
    }

    /// Set `command` up so that the process it spawns, and every process
    /// that one starts, is recorded.
    pub fn prepare(&self, command: &mut Command) -> io::Result<Prepared> {
        self.0
            .prepare(command)
            .map(|held| Prepared { _held: held })
    }

    /// Stop recording and return what was recorded, or `None` when some of
    /// it could not be observed: a process ran unrecorded, or made a call
    /// the recorder could not decode.
    ///
    /// Processes a prepared command left running keep running, but what
    /// they access from now on is not recorded.
    #[must_use]
    pub fn finish(self) -> Option<FileAccesses> {
        self.0.finish()
    }
}
