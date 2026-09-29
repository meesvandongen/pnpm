//! The library pnpm loads into every process of a recorded tree on macOS
//! (through `DYLD_INSERT_LIBRARIES`) and Windows (through Detours). It
//! logs the file accesses of its process to the directory
//! `PNPM_FS_ACCESS_LOG` names, and makes sure the
//! processes its process starts load it too. Other platforms build an
//! empty library.

#[cfg(any(windows, test))]
mod dos_path;
#[cfg(any(target_os = "macos", all(test, unix)))]
mod launch;
#[cfg(any(windows, target_os = "macos"))]
mod log;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as os;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as os;
