//! `execve` and `posix_spawn`, interposed. macOS strips
//! `DYLD_INSERT_LIBRARIES` from the programs it protects (under `/bin`,
//! `/usr/bin`, and the like), which would run them unrecorded. So before
//! the call, a protected shell is swapped for pnpm's shell, a protected
//! core utility for pnpm's core utilities, and a script whose interpreter
//! is one of those runs under the swapped interpreter. Any other protected
//! program runs unrecorded, and never logging that it began, it makes the
//! record incomplete. The hook's variables are kept in the environment of
//! whatever runs.

use super::{
    SETUP, Setup, absolute,
    interpose::interpose,
    launch::{pointers, shebang, strings, with_hook_env},
    log_path,
};
use libc::{c_char, c_int, pid_t, posix_spawn_file_actions_t, posix_spawnattr_t};
use pnpm_fs_access_protocol::{Access, Event};
use std::{
    ffi::{CStr, CString, OsStr},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

unsafe extern "C" {
    static environ: *const *const c_char;
}

const PROTECTED_DIRS: [&str; 6] =
    ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/libexec", "/System"];
const SHELLS: [&str; 3] = ["sh", "bash", "dash"];

/// The programs uutils' `coreutils` runs, by the name it is invoked as.
const COREUTILS: [&str; 107] = [
    "[",
    "arch",
    "b2sum",
    "base32",
    "base64",
    "basename",
    "basenc",
    "cat",
    "chgrp",
    "chmod",
    "chown",
    "chroot",
    "cksum",
    "comm",
    "cp",
    "csplit",
    "cut",
    "date",
    "dd",
    "df",
    "dir",
    "dircolors",
    "dirname",
    "du",
    "echo",
    "env",
    "expand",
    "expr",
    "factor",
    "false",
    "fmt",
    "fold",
    "groups",
    "hashsum",
    "head",
    "hostid",
    "hostname",
    "id",
    "install",
    "join",
    "kill",
    "link",
    "ln",
    "logname",
    "ls",
    "md5sum",
    "mkdir",
    "mkfifo",
    "mknod",
    "mktemp",
    "more",
    "mv",
    "nice",
    "nl",
    "nohup",
    "nproc",
    "numfmt",
    "od",
    "paste",
    "pathchk",
    "pinky",
    "pr",
    "printenv",
    "printf",
    "ptx",
    "pwd",
    "readlink",
    "realpath",
    "rm",
    "rmdir",
    "seq",
    "sha1sum",
    "sha224sum",
    "sha256sum",
    "sha384sum",
    "sha512sum",
    "shred",
    "shuf",
    "sleep",
    "sort",
    "split",
    "stat",
    "stdbuf",
    "stty",
    "sum",
    "sync",
    "tac",
    "tail",
    "tee",
    "test",
    "timeout",
    "touch",
    "tr",
    "true",
    "truncate",
    "tsort",
    "tty",
    "uname",
    "unexpand",
    "uniq",
    "unlink",
    "uptime",
    "users",
    "vdir",
    "wc",
    "who",
    "whoami",
];

/// What actually runs: the program, its arguments, and its environment,
/// with the pointer arrays the call takes.
struct Launch {
    image: PathBuf,
    program: CString,
    _argv: Vec<CString>,
    argv_ptrs: Vec<*const c_char>,
    _envp: Vec<CString>,
    envp_ptrs: Vec<*const c_char>,
}

/// # Safety
///
/// `argv` and `envp` are null-terminated arrays of NUL-terminated strings;
/// `envp` may be null, for this process's environment.
unsafe fn launch(
    setup: &Setup,
    image: PathBuf,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> Option<Launch> {
    // SAFETY: the caller's guarantee.
    let mut args = unsafe { strings(argv) };
    let (program, prefix) = substitute(setup, &image);
    if !prefix.is_empty() {
        // The script runs under the swapped interpreter: its arguments
        // follow the interpreter's, after the script itself.
        let rest = args.split_off(args.len().min(1));
        args = prefix;
        args.push(CString::new(image.as_os_str().as_bytes()).ok()?);
        args.extend(rest);
    }
    // SAFETY: the caller's guarantee; this process's own environment when
    // the call names none.
    let env = unsafe { strings(if envp.is_null() { environ } else { envp }) };
    let env = with_hook_env(setup, env);
    let argv_ptrs = pointers(&args);
    let envp_ptrs = pointers(&env);
    Some(Launch {
        image,
        program: CString::new(program.as_os_str().as_bytes()).ok()?,
        _argv: args,
        argv_ptrs,
        _envp: env,
        envp_ptrs,
    })
}

/// The program to run for `image`, and, for a script whose interpreter is
/// swapped, the arguments that come before the script.
fn substitute(setup: &Setup, image: &Path) -> (PathBuf, Vec<CString>) {
    if let Some(program) = swapped(setup, image) {
        return (program, Vec::new());
    }
    let Some((interpreter, argument)) = shebang(image) else {
        return (image.to_path_buf(), Vec::new());
    };
    let Some(program) = swapped(setup, &interpreter) else {
        return (image.to_path_buf(), Vec::new());
    };
    let mut prefix: Vec<CString> =
        CString::new(interpreter.as_os_str().as_bytes()).into_iter().collect();
    prefix.extend(argument);
    (program, prefix)
}

/// pnpm's stand-in for a protected program, when it has one.
fn swapped(setup: &Setup, program: &Path) -> Option<PathBuf> {
    let dir = program.parent()?;
    if !PROTECTED_DIRS
        .iter()
        .any(|protected| dir == Path::new(protected))
    {
        return None;
    }
    let name = program.file_name()?.to_str()?;
    let stand_in = if SHELLS.contains(&name) {
        &setup.shell
    } else if COREUTILS.contains(&name) {
        &setup.coreutils
    } else {
        return None;
    };
    Some(PathBuf::from(OsStr::from_bytes(stand_in)))
}

/// The absolute path of the program a call names.
///
/// # Safety
///
/// `path` is null or NUL-terminated.
unsafe fn program_path(path: *const c_char) -> Option<PathBuf> {
    if path.is_null() {
        return None;
    }
    // SAFETY: the caller's guarantee.
    absolute(libc::AT_FDCWD, unsafe { CStr::from_ptr(path) }.to_bytes())
}

unsafe extern "C" fn hook_execve(
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    let Some(setup) = SETUP.get() else {
        // SAFETY: the call as the process made it.
        return unsafe { libc::execve(path, argv, envp) };
    };
    // SAFETY: the arguments the process passed.
    let launch = unsafe { program_path(path).and_then(|image| launch(setup, image, argv, envp)) };
    let Some(launch) = launch else {
        crate::log::write(Event::Unrecorded);
        // SAFETY: the call as the process made it.
        return unsafe { libc::execve(path, argv, envp) };
    };
    log_path(Access::Read, &launch.image);
    crate::log::write(Event::Executing { image: launch.image.as_os_str().as_bytes() });
    // SAFETY: the launch's arrays are null-terminated and live across the
    // call.
    let result = unsafe {
        libc::execve(launch.program.as_ptr(), launch.argv_ptrs.as_ptr(), launch.envp_ptrs.as_ptr())
    };
    crate::log::write(Event::ExecFailed);
    result
}
interpose!(hook_execve => libc::execve);

/// # Safety
///
/// The arguments of a `posix_spawn` call, with `image` the program's
/// absolute path.
unsafe fn spawn(
    setup: &Setup,
    image: PathBuf,
    pid: *mut pid_t,
    actions: *const posix_spawn_file_actions_t,
    attributes: *const posix_spawnattr_t,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> Option<c_int> {
    // SAFETY: the caller's guarantee.
    let launch = unsafe { launch(setup, image, argv, envp)? };
    let mut flags: libc::c_short = 0;
    // SAFETY: the attributes the process passed, when it passed any.
    let replaces = !attributes.is_null()
        && unsafe { libc::posix_spawnattr_getflags(attributes, &raw mut flags) } == 0
        && flags & libc::POSIX_SPAWN_SETEXEC as libc::c_short != 0;
    log_path(Access::Read, &launch.image);
    let image = launch.image.as_os_str().as_bytes();
    if replaces {
        crate::log::write(Event::Executing { image });
    }
    // SAFETY: the process's arguments, with the launch's arrays, which are
    // null-terminated and live across the call.
    let result = unsafe {
        libc::posix_spawn(
            pid,
            launch.program.as_ptr(),
            actions,
            attributes,
            launch.argv_ptrs.as_ptr().cast(),
            launch.envp_ptrs.as_ptr().cast(),
        )
    };
    if replaces {
        crate::log::write(Event::ExecFailed);
    } else if result == 0 && !pid.is_null() {
        // SAFETY: a successful call wrote the child's pid.
        let child = unsafe { *pid } as u32;
        crate::log::write(Event::Spawned { child, image });
    }
    Some(result)
}

unsafe extern "C" fn hook_posix_spawn(
    pid: *mut pid_t,
    path: *const c_char,
    actions: *const posix_spawn_file_actions_t,
    attributes: *const posix_spawnattr_t,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
) -> c_int {
    let (argv, envp) = (argv.cast::<*const c_char>(), envp.cast::<*const c_char>());
    // SAFETY: the arguments the process passed.
    let spawned = unsafe {
        SETUP
            .get()
            .zip(program_path(path))
            .and_then(|(setup, image)| spawn(setup, image, pid, actions, attributes, argv, envp))
    };
    // SAFETY: the call as the process made it, when it could not be
    // recorded.
    spawned.unwrap_or_else(|| unsafe {
        unrecorded_spawn(
            pid,
            path,
            actions,
            attributes,
            argv.cast(),
            envp.cast(),
            libc::posix_spawn,
        )
    })
}
interpose!(hook_posix_spawn => libc::posix_spawn);

unsafe extern "C" fn hook_posix_spawnp(
    pid: *mut pid_t,
    file: *const c_char,
    actions: *const posix_spawn_file_actions_t,
    attributes: *const posix_spawnattr_t,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
) -> c_int {
    let (argv_const, envp_const) = (argv.cast::<*const c_char>(), envp.cast::<*const c_char>());
    // SAFETY: the arguments the process passed.
    let spawned = unsafe {
        SETUP
            .get()
            .zip(search_path(file))
            .and_then(|(setup, image)| {
                spawn(setup, image, pid, actions, attributes, argv_const, envp_const)
            })
    };
    // SAFETY: as in `hook_posix_spawn`.
    spawned.unwrap_or_else(|| unsafe {
        unrecorded_spawn(pid, file, actions, attributes, argv, envp, libc::posix_spawnp)
    })
}
interpose!(hook_posix_spawnp => libc::posix_spawnp);

type Spawn = unsafe extern "C" fn(
    *mut pid_t,
    *const c_char,
    *const posix_spawn_file_actions_t,
    *const posix_spawnattr_t,
    *const *mut c_char,
    *const *mut c_char,
) -> c_int;

/// A spawn the hook could not take over: it runs as made, and the record
/// says it is incomplete.
///
/// # Safety
///
/// The arguments of a `posix_spawn` call.
unsafe fn unrecorded_spawn(
    pid: *mut pid_t,
    path: *const c_char,
    actions: *const posix_spawn_file_actions_t,
    attributes: *const posix_spawnattr_t,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
    original: Spawn,
) -> c_int {
    if SETUP.get().is_some() {
        crate::log::write(Event::Unrecorded);
    }
    // SAFETY: the caller's guarantee.
    unsafe { original(pid, path, actions, attributes, argv, envp) }
}

/// The program `posix_spawnp` would run for `file`: `file` itself when it
/// has a slash, else the first executable of that name on `PATH`.
///
/// # Safety
///
/// `file` is null or NUL-terminated.
unsafe fn search_path(file: *const c_char) -> Option<PathBuf> {
    if file.is_null() {
        return None;
    }
    // SAFETY: the caller's guarantee.
    let name = unsafe { CStr::from_ptr(file) }.to_bytes();
    if name.contains(&b'/') {
        return absolute(libc::AT_FDCWD, name);
    }
    let path = std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into());
    std::env::split_paths(&path)
        .map(|dir| dir.join(OsStr::from_bytes(name)))
        .find(|candidate| is_executable(candidate))
        .and_then(|candidate| absolute(libc::AT_FDCWD, candidate.as_os_str().as_bytes()))
}

fn is_executable(path: &Path) -> bool {
    let Ok(path) = CString::new(path.as_os_str().as_bytes()) else { return false };
    // SAFETY: `path` is NUL-terminated. The dylib's own call is not
    // interposed.
    let runnable = unsafe { libc::access(path.as_ptr(), libc::X_OK) == 0 };
    runnable
        && std::fs::metadata(OsStr::from_bytes(path.as_bytes()))
            .is_ok_and(|metadata| metadata.is_file())
}
