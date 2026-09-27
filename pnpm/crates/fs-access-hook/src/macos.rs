//! The macOS hook: a dylib that `DYLD_INSERT_LIBRARIES` loads into every
//! process of the recorded tree. It interposes the file system functions
//! of `libSystem`, and the `exec` and `posix_spawn` functions, which keep
//! the dylib in the environment of every process started and swap in
//! pnpm's own shell and core utilities for the system's (macOS strips the
//! variable from the system's binaries).

mod exec;
mod files;
mod interpose;
mod launch;
mod shims;

use pnpm_fs_access_protocol::{Access, Event, LOG_DIR_ENV, PathState};
use std::{
    ffi::{CStr, OsStr, c_char, c_int},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    sync::{
        OnceLock,
        atomic::{AtomicI32, Ordering},
    },
};

/// The environment variables pnpm sets for the hook, besides
/// [`LOG_DIR_ENV`]: the shell and the core utilities to run in place of
/// the system's.
pub(crate) const SHELL_ENV: &str = "PNPM_FS_ACCESS_SHELL";
pub(crate) const COREUTILS_ENV: &str = "PNPM_FS_ACCESS_COREUTILS";
pub(crate) const INSERT_ENV: &str = "DYLD_INSERT_LIBRARIES";

static LOG_FD: AtomicI32 = AtomicI32::new(-1);

/// The variables this process was started with, handed on to the
/// processes it starts.
pub(crate) struct Setup {
    pub(crate) log_dir: Vec<u8>,
    pub(crate) hook: Vec<u8>,
    pub(crate) shell: Vec<u8>,
    pub(crate) coreutils: Vec<u8>,
}

pub(crate) static SETUP: OnceLock<Setup> = OnceLock::new();

#[used]
#[unsafe(link_section = "__DATA,__mod_init_func")]
static INIT: extern "C" fn() = init;

/// Runs when dyld loads the dylib, before the program's own code.
extern "C" fn init() {
    let var = |name: &str| std::env::var_os(name).map(|value| value.as_bytes().to_vec());
    let (Some(log_dir), Some(hook), Some(shell), Some(coreutils)) = (
        var(LOG_DIR_ENV),
        var(INSERT_ENV).and_then(|value| own_entry(&value)),
        var(SHELL_ENV),
        var(COREUTILS_ENV),
    ) else {
        return;
    };
    if !open_log(&log_dir) {
        return;
    }
    let _ = SETUP.set(Setup { log_dir, hook, shell, coreutils });
    let image = std::env::current_exe().unwrap_or_default();
    crate::log::write(Event::Began { image: image.as_os_str().as_bytes() });
}

/// This dylib's entry in `DYLD_INSERT_LIBRARIES`, which may list others.
fn own_entry(value: &[u8]) -> Option<Vec<u8>> {
    value
        .split(|byte| *byte == b':')
        .find(|entry| entry.ends_with(b"libpnpm_fs_access_hook.dylib"))
        .map(<[u8]>::to_vec)
}

fn open_log(log_dir: &[u8]) -> bool {
    let name = format!("/{}-{}.log", pid(), now());
    let mut path = log_dir.to_vec();
    path.extend_from_slice(name.as_bytes());
    path.push(0);
    // SAFETY: `path` is NUL-terminated. The dylib's own calls are not
    // interposed.
    let fd = unsafe {
        libc::open(
            path.as_ptr().cast(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_APPEND | libc::O_CLOEXEC,
            0o600,
        )
    };
    LOG_FD.store(fd, Ordering::Relaxed);
    fd >= 0
}

pub(crate) fn pid() -> u32 {
    // SAFETY: no preconditions.
    unsafe { libc::getpid() as u32 }
}

unsafe extern "C" {
    fn mach_absolute_time() -> u64;
}

/// The Mach absolute time, which every process of the machine shares.
pub(crate) fn now() -> u64 {
    // SAFETY: no preconditions.
    unsafe { mach_absolute_time() }
}

pub(crate) fn append(record: &[u8]) {
    let fd = LOG_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        // SAFETY: `record` lives across the call.
        unsafe {
            libc::write(fd, record.as_ptr().cast(), record.len());
        }
    }
}

fn recording() -> bool {
    LOG_FD.load(Ordering::Relaxed) >= 0
}

/// Log an access of the path `path` names relative to `dirfd`.
///
/// # Safety
///
/// `path` is null or a NUL-terminated string.
pub(crate) unsafe fn log_at(access: Access, dirfd: c_int, path: *const c_char) {
    if !recording() || path.is_null() {
        return;
    }
    // SAFETY: the caller's guarantee.
    let name = unsafe { CStr::from_ptr(path) }.to_bytes();
    crate::log::guarded(|| match absolute(dirfd, name) {
        Some(path) => log_path(access, &path),
        None => crate::log::write(Event::Unrecorded),
    });
}

/// Log an access of the directory or file open as `fd`.
pub(crate) fn log_fd(access: Access, fd: c_int) {
    if !recording() {
        return;
    }
    crate::log::guarded(|| match fd_path(fd) {
        Some(path) => log_path(access, &path),
        None => crate::log::write(Event::Unrecorded),
    });
}

pub(crate) fn log_path(access: Access, path: &Path) {
    let bytes = path.as_os_str().as_bytes();
    crate::log::access(access, bytes, || {
        (!matches!(access, Access::Write)).then(|| PathState::of(path))
    });
}

/// `name` made absolute against `dirfd`: the working directory for
/// `AT_FDCWD`, else the directory the descriptor is open on.
pub(crate) fn absolute(dirfd: c_int, name: &[u8]) -> Option<PathBuf> {
    let name = Path::new(OsStr::from_bytes(name));
    if name.is_absolute() {
        return Some(name.to_path_buf());
    }
    let base =
        if dirfd == libc::AT_FDCWD { std::env::current_dir().ok()? } else { fd_path(dirfd)? };
    Some(base.join(name))
}

fn fd_path(fd: c_int) -> Option<PathBuf> {
    let mut buffer = [0u8; libc::PATH_MAX as usize];
    // SAFETY: `F_GETPATH` writes at most `PATH_MAX` bytes into `buffer`.
    if unsafe { libc::fcntl(fd, libc::F_GETPATH, buffer.as_mut_ptr()) } != 0 {
        return None;
    }
    let len = buffer
        .iter()
        .position(|byte| *byte == 0)?;
    Some(PathBuf::from(OsStr::from_bytes(&buffer[..len])))
}
