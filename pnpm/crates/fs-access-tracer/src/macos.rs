//! The macOS recorder. The command runs with `DYLD_INSERT_LIBRARIES`
//! naming the hook dylib, which logs its process's file accesses and keeps
//! itself in the environment of the processes that one starts. macOS
//! strips the variable from its own binaries, so a system shell the
//! command names is swapped for pnpm's, as the hook does for the shells
//! and core utilities the command runs.

use crate::{FileAccesses, Unsupported, artifact::embedded, log::read_logs};
use pnpm_fs_access_protocol::{Event, LOG_DIR_ENV, Record, encode, max_record_len};
use std::{
    ffi::{OsStr, OsString},
    fs::{File, OpenOptions},
    io::{self, Write},
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

pub const IS_SUPPORTED: bool = true;

const SHELL_ENV: &str = "PNPM_FS_ACCESS_SHELL";
const COREUTILS_ENV: &str = "PNPM_FS_ACCESS_COREUTILS";
const INSERT_ENV: &str = "DYLD_INSERT_LIBRARIES";
const PROTECTED_DIRS: [&str; 6] =
    ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/libexec", "/System"];
const SHELLS: [&str; 3] = ["sh", "bash", "dash"];

pub struct Recorder {
    shared: Arc<Shared>,
}

pub struct Prepared {
    shared: Arc<Shared>,
}

struct Shared {
    log_dir: tempfile::TempDir,
    hook: PathBuf,
    shell: PathBuf,
    coreutils: PathBuf,
    /// pnpm's own log, which names the processes it started.
    own_log: Mutex<File>,
    incomplete: AtomicBool,
}

unsafe extern "C" {
    fn mach_absolute_time() -> u64;
}

impl Recorder {
    pub fn new() -> Result<Self, Unsupported> {
        let written = |path: io::Result<PathBuf>| {
            path.map_err(|_| Unsupported("the file access hook could not be written to disk"))
        };
        let hook = written(
            embedded!("libpnpm_fs_access_hook.dylib", "HOOK", executable = false).materialize(),
        )?;
        let shell = written(embedded!("oils-for-unix", "SHELL", executable = true).materialize())?;
        let coreutils =
            written(embedded!("coreutils", "COREUTILS", executable = true).materialize())?;
        let log_dir = tempfile::Builder::new()
            .prefix("pnpm-fs-access-")
            .tempdir()
            .map_err(|_| {
                Unsupported("a directory for the file access logs could not be created")
            })?;
        let own_log = OpenOptions::new()
            .create_new(true)
            .append(true)
            .open(log_dir.path().join("pnpm.log"))
            .map_err(|_| Unsupported("the file access log could not be created"))?;
        Ok(Recorder {
            shared: Arc::new(Shared {
                log_dir,
                hook,
                shell,
                coreutils,
                own_log: Mutex::new(own_log),
                incomplete: AtomicBool::new(false),
            }),
        })
    }

    /// A system shell is swapped for pnpm's, keeping the name it was
    /// invoked as, which is what makes the shell behave as `sh`.
    pub fn command(&self, program: &OsStr) -> Command {
        let resolved = resolve(program);
        let is_system_shell = resolved
            .as_deref()
            .is_some_and(|path| {
                path.parent()
                    .is_some_and(|dir| {
                        PROTECTED_DIRS
                            .iter()
                            .any(|protected| dir == Path::new(protected))
                    })
                    && path
                        .file_name()
                        .and_then(OsStr::to_str)
                        .is_some_and(|name| SHELLS.contains(&name))
            });
        if !is_system_shell {
            return Command::new(program);
        }
        let mut command = Command::new(&self.shared.shell);
        command.arg0(program);
        command
    }

    pub fn prepare(&self, command: &mut Command) -> io::Result<Prepared> {
        let inherited = command
            .get_envs()
            .find(|(name, _)| *name == OsStr::new(INSERT_ENV))
            .map_or_else(
                || std::env::var_os(INSERT_ENV),
                |(_, value)| value.map(OsStr::to_os_string),
            );
        let mut insert = OsString::new();
        if let Some(inherited) = inherited.filter(|value| !value.is_empty()) {
            insert.push(inherited);
            insert.push(":");
        }
        insert.push(&self.shared.hook);
        command
            .env(INSERT_ENV, insert)
            .env(LOG_DIR_ENV, self.shared.log_dir.path())
            .env(SHELL_ENV, &self.shared.shell)
            .env(COREUTILS_ENV, &self.shared.coreutils);
        Ok(Prepared { shared: Arc::clone(&self.shared) })
    }

    pub fn finish(self) -> Option<FileAccesses> {
        let accesses = read_logs(self.shared.log_dir.path()).ok().flatten()?;
        (!self.shared.incomplete.load(Ordering::SeqCst)).then_some(accesses)
    }
}

impl Prepared {
    /// Log the process as spawned by pnpm, so the record is incomplete
    /// unless the hook starts in it.
    pub fn started(self, child: &Child) {
        let image: &[u8] = &[];
        // SAFETY: no preconditions.
        let time = unsafe { mach_absolute_time() };
        let record = Record {
            pid: std::process::id(),
            time,
            event: Event::Spawned { child: child.id(), image },
        };
        let mut buffer = vec![0u8; max_record_len(0)];
        let written = encode(&record, &mut buffer)
            .is_some_and(|len| {
                self.shared.own_log
                    .lock()
                    .expect("the log lock is not poisoned")
                    .write_all(&buffer[..len])
                    .is_ok()
            });
        if !written {
            self.shared.incomplete.store(true, Ordering::SeqCst);
        }
    }
}

/// The path `program` runs from: itself when it names one, else the first
/// match on `PATH`.
fn resolve(program: &OsStr) -> Option<PathBuf> {
    let program = Path::new(program);
    if program.components().count() > 1 {
        return Some(program.to_path_buf());
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
}

#[cfg(test)]
mod tests;
