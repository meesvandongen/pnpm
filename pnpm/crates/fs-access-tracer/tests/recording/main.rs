//! The recorder on every platform it supports, driven the way tasks drive
//! it: Node's file system API, programs started in several ways, and paths
//! at the edges of what each platform accepts.

mod helper;
mod node;
mod paths;
mod processes;

use pnpm_fs_access_tracer::{FileAccesses, Recorder};
use std::{
    collections::BTreeSet,
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
};

/// Run `program` with `args` in `dir` under a recorder.
fn record(dir: &Path, program: &OsStr, args: &[&OsStr]) -> (ExitStatus, Option<FileAccesses>) {
    let recorder = Recorder::new().expect("this system supports recording");
    let mut command = recorder.command(program);
    command.args(args).current_dir(dir);
    run(recorder, command)
}

fn run(recorder: Recorder, mut command: Command) -> (ExitStatus, Option<FileAccesses>) {
    let prepared = recorder.prepare(&mut command).expect("prepare the command");
    let mut child = command.spawn().expect("run the command");
    prepared.started(&child);
    let status = child.wait().expect("wait for the command");
    let accesses = recorder.finish();
    dbg!(&accesses);
    (status, accesses)
}

/// Run a Node script in `dir` and return what it accessed, which must all
/// have been observed.
fn node(dir: &Path, script: &str) -> FileAccesses {
    let script = format!(
        "const fs = require('node:fs'); const child_process = require('node:child_process'); {script}"
    );
    let (status, accesses) = record(dir, "node".as_ref(), &["-e".as_ref(), script.as_ref()]);
    assert!(status.success(), "{script} exits cleanly");
    accesses.expect("every access is recorded")
}

/// A fresh directory, by the name the file system gives it.
fn fixture() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let dir = fs::canonicalize(temp.path()).unwrap();
    let dir = dir
        .to_str()
        .and_then(|text| text.strip_prefix(r"\\?\"))
        .map_or_else(|| dir.clone(), PathBuf::from);
    (temp, dir)
}

/// A path in one spelling, whether it was recorded as a process named it
/// (which on Windows may use short 8.3 components) or from a handle.
fn normalized(path: &Path) -> String {
    let resolved = fs::canonicalize(path)
        .or_else(|_| {
            let parent = fs::canonicalize(path.parent().unwrap_or(path))?;
            Ok::<_, std::io::Error>(parent.join(path.file_name().unwrap_or_default()))
        })
        .unwrap_or_else(|_| path.to_path_buf());
    let text = resolved.to_string_lossy();
    let text = text.strip_prefix(r"\\?\").unwrap_or(&text);
    if cfg!(windows) { text.to_lowercase() } else { text.to_string() }
}

fn contains(paths: &BTreeSet<PathBuf>, path: &Path) -> bool {
    let expected = normalized(path);
    paths
        .iter()
        .any(|recorded| normalized(recorded) == expected)
}

/// Whether the accesses make `path` an input: read, or probed for.
fn observed(accesses: &FileAccesses, path: &Path) -> bool {
    contains(&accesses.reads, path) || contains(&accesses.probes, path)
}
