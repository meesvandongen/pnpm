//! The `libSystem` file system functions, interposed. Each logs the access
//! and then makes the call as it was made.

use super::{interpose::interpose, log_at, log_fd};
use libc::{FILE, c_char, c_int, c_long, c_void, mode_t, off_t, size_t, ssize_t, stat};
use pnpm_fs_access_protocol::Access;

unsafe extern "C" {
    #[link_name = "open$NOCANCEL"]
    fn open_nocancel(path: *const c_char, flags: c_int, ...) -> c_int;
    #[link_name = "openat$NOCANCEL"]
    fn openat_nocancel(dirfd: c_int, path: *const c_char, flags: c_int, ...) -> c_int;
    fn __getdirentries64(fd: c_int, buffer: *mut c_void, len: size_t, base: *mut i64) -> ssize_t;
    fn getattrlistbulk(
        dirfd: c_int,
        list: *mut c_void,
        buffer: *mut c_void,
        size: size_t,
        options: u64,
    ) -> c_int;
    fn getattrlistat(
        dirfd: c_int,
        path: *const c_char,
        list: *mut c_void,
        buffer: *mut c_void,
        size: size_t,
        options: c_long,
    ) -> c_int;
    fn renamex_np(from: *const c_char, to: *const c_char, flags: u32) -> c_int;
    fn renameatx_np(
        from_fd: c_int,
        from: *const c_char,
        to_fd: c_int,
        to: *const c_char,
        flags: u32,
    ) -> c_int;
    fn clonefile(from: *const c_char, to: *const c_char, flags: u32) -> c_int;
    fn clonefileat(
        from_fd: c_int,
        from: *const c_char,
        to_fd: c_int,
        to: *const c_char,
        flags: u32,
    ) -> c_int;
    fn fclonefileat(from: c_int, to_fd: c_int, to: *const c_char, flags: u32) -> c_int;
}

/// How an open with these flags uses its path.
fn open_access(flags: c_int) -> Access {
    let mode = flags & libc::O_ACCMODE;
    if mode == libc::O_RDWR && flags & libc::O_TRUNC == 0 {
        return Access::ReadWrite;
    }
    if mode != libc::O_RDONLY || flags & (libc::O_CREAT | libc::O_TRUNC) != 0 {
        return Access::Write;
    }
    if flags & (libc::O_DIRECTORY | libc::O_SYMLINK | libc::O_EVTONLY) != 0 {
        return Access::Probe;
    }
    Access::Read
}

/// How an `fopen` mode string uses its path.
fn fopen_access(mode: *const c_char) -> Access {
    if mode.is_null() {
        return Access::Read;
    }
    // SAFETY: `fopen` takes a NUL-terminated mode.
    let mode = unsafe { std::ffi::CStr::from_ptr(mode) }.to_bytes();
    match (mode.first(), mode.contains(&b'+')) {
        (Some(b'r'), true) => Access::ReadWrite,
        (Some(b'r'), false) => Access::Read,
        _ => Access::Write,
    }
}

/// The part of `open` and `openat` after the variadic mode has been read
/// into a register; see [`super::shims`].
#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn pnpm_open_hook(
    path: *const c_char,
    flags: c_int,
    mode: c_int,
) -> c_int {
    // SAFETY: the arguments the process passed.
    unsafe {
        log_at(open_access(flags), libc::AT_FDCWD, path);
        libc::open(path, flags, mode)
    }
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn pnpm_openat_hook(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: c_int,
) -> c_int {
    // SAFETY: the arguments the process passed.
    unsafe {
        log_at(open_access(flags), dirfd, path);
        libc::openat(dirfd, path, flags, mode)
    }
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn pnpm_open_nocancel_hook(
    path: *const c_char,
    flags: c_int,
    mode: c_int,
) -> c_int {
    // SAFETY: the arguments the process passed.
    unsafe {
        log_at(open_access(flags), libc::AT_FDCWD, path);
        open_nocancel(path, flags, mode)
    }
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn pnpm_openat_nocancel_hook(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: c_int,
) -> c_int {
    // SAFETY: the arguments the process passed.
    unsafe {
        log_at(open_access(flags), dirfd, path);
        openat_nocancel(dirfd, path, flags, mode)
    }
}

interpose!(super::shims::open_entry => libc::open);
interpose!(super::shims::openat_entry => libc::openat);
interpose!(super::shims::open_nocancel_entry => open_nocancel);
interpose!(super::shims::openat_nocancel_entry => openat_nocancel);

unsafe extern "C" fn hook_fopen(path: *const c_char, mode: *const c_char) -> *mut FILE {
    // SAFETY: the arguments the process passed.
    unsafe {
        log_at(fopen_access(mode), libc::AT_FDCWD, path);
        libc::fopen(path, mode)
    }
}
interpose!(hook_fopen => libc::fopen);

unsafe extern "C" fn hook_freopen(
    path: *const c_char,
    mode: *const c_char,
    stream: *mut FILE,
) -> *mut FILE {
    // SAFETY: the arguments the process passed.
    unsafe {
        log_at(fopen_access(mode), libc::AT_FDCWD, path);
        libc::freopen(path, mode, stream)
    }
}
interpose!(hook_freopen => libc::freopen);

/// Interpose a function whose first argument is a path it probes.
macro_rules! probe {
    ($hook:ident => $original:path, ($($arg:ident: $type:ty),*) -> $ret:ty) => {
        unsafe extern "C" fn $hook(path: *const c_char, $($arg: $type),*) -> $ret {
            // SAFETY: the arguments the process passed.
            unsafe {
                log_at(Access::Probe, libc::AT_FDCWD, path);
                $original(path, $($arg),*)
            }
        }
        interpose!($hook => $original);
    };
}

/// Interpose a function whose first two arguments are a directory
/// descriptor and a path relative to it, which it `$access`es.
macro_rules! at {
    ($access:ident, $hook:ident => $original:path, ($($arg:ident: $type:ty),*) -> $ret:ty) => {
        unsafe extern "C" fn $hook(dirfd: c_int, path: *const c_char, $($arg: $type),*) -> $ret {
            // SAFETY: the arguments the process passed.
            unsafe {
                log_at(Access::$access, dirfd, path);
                $original(dirfd, path, $($arg),*)
            }
        }
        interpose!($hook => $original);
    };
}

/// Interpose a function whose first argument is a path it writes.
macro_rules! writes {
    ($hook:ident => $original:path, ($($arg:ident: $type:ty),*) -> $ret:ty) => {
        unsafe extern "C" fn $hook(path: *const c_char, $($arg: $type),*) -> $ret {
            // SAFETY: the arguments the process passed.
            unsafe {
                log_at(Access::Write, libc::AT_FDCWD, path);
                $original(path, $($arg),*)
            }
        }
        interpose!($hook => $original);
    };
}

probe!(hook_stat => libc::stat, (buffer: *mut stat) -> c_int);
probe!(hook_lstat => libc::lstat, (buffer: *mut stat) -> c_int);
probe!(hook_access => libc::access, (mode: c_int) -> c_int);
probe!(hook_readlink => libc::readlink, (buffer: *mut c_char, size: size_t) -> ssize_t);
probe!(
    hook_getattrlist => libc::getattrlist,
    (list: *mut c_void, buffer: *mut c_void, size: size_t, options: u32) -> c_int
);
at!(Probe, hook_fstatat => libc::fstatat, (buffer: *mut stat, flags: c_int) -> c_int);
at!(Probe, hook_faccessat => libc::faccessat, (mode: c_int, flags: c_int) -> c_int);
at!(Probe, hook_readlinkat => libc::readlinkat, (buffer: *mut c_char, size: size_t) -> ssize_t);
at!(
    Probe, hook_getattrlistat => getattrlistat,
    (list: *mut c_void, buffer: *mut c_void, size: size_t, options: c_long) -> c_int
);
writes!(hook_mkdir => libc::mkdir, (mode: mode_t) -> c_int);
writes!(hook_rmdir => libc::rmdir, () -> c_int);
writes!(hook_unlink => libc::unlink, () -> c_int);
writes!(hook_truncate => libc::truncate, (len: off_t) -> c_int);
at!(Write, hook_mkdirat => libc::mkdirat, (mode: mode_t) -> c_int);
at!(Write, hook_unlinkat => libc::unlinkat, (flags: c_int) -> c_int);

unsafe extern "C" fn hook_getdirentries64(
    fd: c_int,
    buffer: *mut c_void,
    len: size_t,
    base: *mut i64,
) -> ssize_t {
    log_fd(Access::List, fd);
    // SAFETY: the call as the process made it.
    unsafe { __getdirentries64(fd, buffer, len, base) }
}
interpose!(hook_getdirentries64 => __getdirentries64);

unsafe extern "C" fn hook_getattrlistbulk(
    dirfd: c_int,
    list: *mut c_void,
    buffer: *mut c_void,
    size: size_t,
    options: u64,
) -> c_int {
    log_fd(Access::List, dirfd);
    // SAFETY: the call as the process made it.
    unsafe { getattrlistbulk(dirfd, list, buffer, size, options) }
}
interpose!(hook_getattrlistbulk => getattrlistbulk);

/// Log both paths of a call that moves `from` to `to`, or of one that
/// only creates `to` when `from` is `None`.
///
/// # Safety
///
/// The paths are null or NUL-terminated.
unsafe fn log_pair(from: Option<(c_int, *const c_char, Access)>, to: (c_int, *const c_char)) {
    // SAFETY: the caller's guarantee.
    unsafe {
        if let Some((dirfd, path, access)) = from {
            log_at(access, dirfd, path);
        }
        log_at(Access::Write, to.0, to.1);
    }
}

const CWD: c_int = libc::AT_FDCWD;

unsafe extern "C" fn hook_rename(from: *const c_char, to: *const c_char) -> c_int {
    // SAFETY: the arguments the process passed.
    unsafe {
        log_pair(Some((CWD, from, Access::Write)), (CWD, to));
        libc::rename(from, to)
    }
}
interpose!(hook_rename => libc::rename);

unsafe extern "C" fn hook_renameat(
    from_fd: c_int,
    from: *const c_char,
    to_fd: c_int,
    to: *const c_char,
) -> c_int {
    // SAFETY: the arguments the process passed.
    unsafe {
        log_pair(Some((from_fd, from, Access::Write)), (to_fd, to));
        libc::renameat(from_fd, from, to_fd, to)
    }
}
interpose!(hook_renameat => libc::renameat);

unsafe extern "C" fn hook_renamex_np(from: *const c_char, to: *const c_char, flags: u32) -> c_int {
    // SAFETY: the arguments the process passed.
    unsafe {
        log_pair(Some((CWD, from, Access::Write)), (CWD, to));
        renamex_np(from, to, flags)
    }
}
interpose!(hook_renamex_np => renamex_np);

unsafe extern "C" fn hook_renameatx_np(
    from_fd: c_int,
    from: *const c_char,
    to_fd: c_int,
    to: *const c_char,
    flags: u32,
) -> c_int {
    // SAFETY: the arguments the process passed.
    unsafe {
        log_pair(Some((from_fd, from, Access::Write)), (to_fd, to));
        renameatx_np(from_fd, from, to_fd, to, flags)
    }
}
interpose!(hook_renameatx_np => renameatx_np);

unsafe extern "C" fn hook_link(from: *const c_char, to: *const c_char) -> c_int {
    // SAFETY: the arguments the process passed.
    unsafe {
        log_pair(None, (CWD, to));
        libc::link(from, to)
    }
}
interpose!(hook_link => libc::link);

unsafe extern "C" fn hook_linkat(
    from_fd: c_int,
    from: *const c_char,
    to_fd: c_int,
    to: *const c_char,
    flags: c_int,
) -> c_int {
    // SAFETY: the arguments the process passed.
    unsafe {
        log_pair(None, (to_fd, to));
        libc::linkat(from_fd, from, to_fd, to, flags)
    }
}
interpose!(hook_linkat => libc::linkat);

unsafe extern "C" fn hook_symlink(target: *const c_char, path: *const c_char) -> c_int {
    // SAFETY: the arguments the process passed.
    unsafe {
        log_pair(None, (CWD, path));
        libc::symlink(target, path)
    }
}
interpose!(hook_symlink => libc::symlink);

unsafe extern "C" fn hook_symlinkat(
    target: *const c_char,
    dirfd: c_int,
    path: *const c_char,
) -> c_int {
    // SAFETY: the arguments the process passed.
    unsafe {
        log_pair(None, (dirfd, path));
        libc::symlinkat(target, dirfd, path)
    }
}
interpose!(hook_symlinkat => libc::symlinkat);

unsafe extern "C" fn hook_clonefile(from: *const c_char, to: *const c_char, flags: u32) -> c_int {
    // SAFETY: the arguments the process passed.
    unsafe {
        log_pair(Some((CWD, from, Access::Read)), (CWD, to));
        clonefile(from, to, flags)
    }
}
interpose!(hook_clonefile => clonefile);

unsafe extern "C" fn hook_clonefileat(
    from_fd: c_int,
    from: *const c_char,
    to_fd: c_int,
    to: *const c_char,
    flags: u32,
) -> c_int {
    // SAFETY: the arguments the process passed.
    unsafe {
        log_pair(Some((from_fd, from, Access::Read)), (to_fd, to));
        clonefileat(from_fd, from, to_fd, to, flags)
    }
}
interpose!(hook_clonefileat => clonefileat);

unsafe extern "C" fn hook_fclonefileat(
    from: c_int,
    to_fd: c_int,
    to: *const c_char,
    flags: u32,
) -> c_int {
    log_fd(Access::Read, from);
    // SAFETY: the arguments the process passed.
    unsafe {
        log_pair(None, (to_fd, to));
        fclonefileat(from, to_fd, to, flags)
    }
}
interpose!(hook_fclonefileat => fclonefileat);
