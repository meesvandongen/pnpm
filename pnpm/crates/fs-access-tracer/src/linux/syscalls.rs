use super::tracee::Tracee;
use libc::c_int;
use std::path::PathBuf;

/// What a traced system call does to the file system, as far as the
/// record is concerned.
pub(super) enum Effect {
    Read(PathBuf),
    Probe(PathBuf),
    List(PathBuf),
    /// Recorded only once the call succeeds.
    Write(Vec<PathBuf>),
}

#[cfg(target_arch = "x86_64")]
const SYS_RENAMEAT: i64 = libc::SYS_renameat;
/// arm64 keeps `renameat`, which glibc's headers leave out.
#[cfg(target_arch = "aarch64")]
const SYS_RENAMEAT: i64 = 38;

const AT_SYSCALLS: [i64; 15] = [
    libc::SYS_openat,
    libc::SYS_openat2,
    libc::SYS_newfstatat,
    libc::SYS_statx,
    libc::SYS_faccessat,
    libc::SYS_faccessat2,
    libc::SYS_readlinkat,
    libc::SYS_getdents64,
    libc::SYS_mkdirat,
    libc::SYS_unlinkat,
    SYS_RENAMEAT,
    libc::SYS_renameat2,
    libc::SYS_linkat,
    libc::SYS_symlinkat,
    libc::SYS_truncate,
];

#[cfg(target_arch = "x86_64")]
const LEGACY_SYSCALLS: [i64; 13] = [
    libc::SYS_open,
    libc::SYS_creat,
    libc::SYS_stat,
    libc::SYS_lstat,
    libc::SYS_access,
    libc::SYS_readlink,
    libc::SYS_getdents,
    libc::SYS_mkdir,
    libc::SYS_rmdir,
    libc::SYS_unlink,
    libc::SYS_rename,
    libc::SYS_link,
    libc::SYS_symlink,
];
#[cfg(target_arch = "aarch64")]
const LEGACY_SYSCALLS: [i64; 0] = [];

/// The system calls the seccomp filter stops at.
pub(super) fn traced_syscalls() -> Vec<i64> {
    AT_SYSCALLS
        .into_iter()
        .chain(LEGACY_SYSCALLS)
        .collect()
}

/// The effect of the system call `number` with `args`, or `None` when it
/// names no path the record can use. `Err` means the call is not one this
/// table knows, so the trace can no longer claim to be complete.
pub(super) fn effect(tracee: Tracee, number: i64, args: &[u64; 6]) -> Result<Option<Effect>, ()> {
    let at = |dirfd: usize, path: usize| tracee.path_at(args[dirfd] as c_int, args[path]);
    let effect = match number {
        libc::SYS_openat => at(0, 1).map(|path| open_effect(path, args[2])),
        libc::SYS_openat2 => {
            at(0, 1).and_then(|path| Some(open_effect(path, tracee.read_u64(args[2])?)))
        }
        libc::SYS_newfstatat
        | libc::SYS_statx
        | libc::SYS_faccessat
        | libc::SYS_faccessat2
        | libc::SYS_readlinkat => at(0, 1).map(Effect::Probe),
        libc::SYS_getdents64 => tracee
            .fd_path(args[0] as c_int)
            .map(Effect::List),
        libc::SYS_mkdirat | libc::SYS_unlinkat => at(0, 1).map(|path| Effect::Write(vec![path])),
        SYS_RENAMEAT | libc::SYS_renameat2 => write_effect([at(0, 1), at(2, 3)]),
        libc::SYS_linkat => write_effect([at(2, 3)]),
        libc::SYS_symlinkat => write_effect([at(1, 2)]),
        libc::SYS_truncate => write_effect([at_cwd(tracee, args[0])]),
        _ => return legacy_effect(tracee, number, args),
    };
    Ok(effect)
}

#[cfg(target_arch = "x86_64")]
fn legacy_effect(tracee: Tracee, number: i64, args: &[u64; 6]) -> Result<Option<Effect>, ()> {
    let path = |index: usize| at_cwd(tracee, args[index]);
    let effect = match number {
        libc::SYS_open => path(0).map(|name| open_effect(name, args[1])),
        libc::SYS_creat
        | libc::SYS_mkdir
        | libc::SYS_rmdir
        | libc::SYS_unlink
        | libc::SYS_symlink => write_effect([path(usize::from(number == libc::SYS_symlink))]),
        libc::SYS_stat | libc::SYS_lstat | libc::SYS_access | libc::SYS_readlink => {
            path(0).map(Effect::Probe)
        }
        libc::SYS_getdents => tracee
            .fd_path(args[0] as c_int)
            .map(Effect::List),
        libc::SYS_rename => write_effect([path(0), path(1)]),
        libc::SYS_link => write_effect([path(1)]),
        _ => return Err(()),
    };
    Ok(effect)
}

#[cfg(target_arch = "aarch64")]
fn legacy_effect(_: Tracee, _: i64, _: &[u64; 6]) -> Result<Option<Effect>, ()> {
    Err(())
}

fn at_cwd(tracee: Tracee, address: u64) -> Option<PathBuf> {
    tracee.path_at(libc::AT_FDCWD, address)
}

fn write_effect<const N: usize>(paths: [Option<PathBuf>; N]) -> Option<Effect> {
    let paths: Vec<PathBuf> = paths.into_iter().flatten().collect();
    (!paths.is_empty()).then_some(Effect::Write(paths))
}

/// An open that may modify the file is a write whether or not it writes;
/// one that yields a directory or `O_PATH` descriptor reads no contents.
fn open_effect(path: PathBuf, flags: u64) -> Effect {
    let flags = flags as c_int;
    if flags & libc::O_ACCMODE != libc::O_RDONLY || flags & (libc::O_CREAT | libc::O_TRUNC) != 0 {
        return Effect::Write(vec![path]);
    }
    if flags & (libc::O_DIRECTORY | libc::O_PATH) != 0 {
        return Effect::Probe(path);
    }
    Effect::Read(path)
}
