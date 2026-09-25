//! The tracer as a process of its own. A caller prefixes the command it
//! wants traced with [`launcher`]; the launched pnpm enters [`try_run`]
//! before anything else, traces the command, writes the trace into the
//! log directory, and exits the way the command did. [`read_traces`]
//! merges what every launch into one directory recorded.

use crate::{FileAccesses, trace_command};
use serde::{Deserialize, Serialize};
use std::{
    ffi::{OsStr, OsString},
    fs, io,
    path::Path,
    process::{Command, ExitStatus},
};

/// The first argument that makes pnpm run as the tracer.
pub const ARG: &str = "--pnpm-internal-trace-file-accesses";

/// One launch's record. Created as incomplete before the command runs, so a
/// launch that dies before writing its trace still leaves a record that
/// says the trace cannot be trusted.
#[derive(Default, Serialize, Deserialize)]
struct TraceLog {
    complete: bool,
    accesses: FileAccesses,
}

/// The command prefix that runs a program, given after it with its
/// arguments, under the tracer: `executable` is the pnpm to launch, and
/// `log_dir` an existing directory the trace is written into.
#[must_use]
pub fn launcher(executable: &Path, log_dir: &Path) -> Vec<OsString> {
    vec![executable.into(), ARG.into(), log_dir.into()]
}

/// Trace the command `argv` names when it is a [`launcher`] invocation,
/// and return the exit code this process should end with. `None` when
/// `argv` is any other pnpm invocation.
#[must_use]
pub fn try_run(argv: &[OsString]) -> Option<i32> {
    let [_, arg, log_dir, program, args @ ..] = argv else { return None };
    if arg != ARG {
        return None;
    }
    let log_file = match create_log(Path::new(log_dir)) {
        Ok(log_file) => log_file,
        Err(error) => {
            eprintln!("pnpm: cannot record the file accesses of {}: {error}", program.display());
            return Some(1);
        }
    };
    let mut command = Command::new(program);
    command.args(args);
    let trace = match trace_command(command) {
        Ok(trace) => trace,
        Err(error) => {
            eprintln!("pnpm: cannot run {}: {error}", program.display());
            return Some(if error.kind() == io::ErrorKind::NotFound { 127 } else { 126 });
        }
    };
    let log = TraceLog { complete: trace.complete, accesses: trace.accesses };
    // A trace that cannot be written leaves the incomplete record behind.
    if let Err(error) = write_log(&log_file, &log) {
        eprintln!("pnpm: cannot record the file accesses of {}: {error}", program.display());
    }
    Some(exit_code(trace.status))
}

/// The accesses recorded by every launch into `log_dir`, or `None` when
/// there were none or any launch's trace is incomplete.
pub fn read_traces(log_dir: &Path) -> io::Result<Option<FileAccesses>> {
    let mut accesses = FileAccesses::default();
    let mut found = false;
    for entry in fs::read_dir(log_dir)? {
        let path = entry?.path();
        if path.extension() != Some(OsStr::new("json")) {
            continue;
        }
        let Ok(log) = serde_json::from_slice::<TraceLog>(&fs::read(&path)?) else {
            return Ok(None);
        };
        if !log.complete {
            return Ok(None);
        }
        accesses.extend(log.accesses);
        found = true;
    }
    Ok(found.then_some(accesses))
}

fn create_log(log_dir: &Path) -> io::Result<std::path::PathBuf> {
    let (_, path) = tempfile::Builder::new()
        .prefix("trace-")
        .suffix(".json")
        .tempfile_in(log_dir)?
        .keep()
        .map_err(|error| error.error)?;
    write_log(&path, &TraceLog::default())?;
    Ok(path)
}

fn write_log(path: &Path, log: &TraceLog) -> io::Result<()> {
    fs::write(path, serde_json::to_vec(log)?)
}

/// The command's exit code, or, for a command killed by a signal, the
/// same death for this process.
fn exit_code(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    if let Some(signal) = std::os::unix::process::ExitStatusExt::signal(&status) {
        // SAFETY: restores the default action and raises the signal on
        // this process, which ends it before `raise` returns for every
        // signal that ended the command.
        unsafe {
            libc::signal(signal, libc::SIG_DFL);
            libc::raise(signal);
        }
        return 128 + signal;
    }
    1
}

#[cfg(test)]
mod tests;
