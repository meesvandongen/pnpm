use super::{TraceLog, launcher, read_traces, try_run, write_log};
use crate::FileAccesses;
use std::{ffi::OsString, fs, path::Path};

fn log_with_read(dir: &Path, name: &str, complete: bool, read: &str) {
    let mut accesses = FileAccesses::default();
    accesses.reads.insert(read.into());
    write_log(&dir.join(name), &TraceLog { complete, accesses }).unwrap();
}

#[test]
fn other_invocations_are_not_the_helper() {
    let argv: Vec<OsString> = ["pnpm", "install"].map(OsString::from).into();
    assert_eq!(try_run(&argv), None);
    let argv: Vec<OsString> = ["pnpm", "run", "a", "b"].map(OsString::from).into();
    assert_eq!(try_run(&argv), None);
}

#[test]
fn traces_of_every_launch_are_merged() {
    let dir = tempfile::tempdir().unwrap();
    log_with_read(dir.path(), "trace-1.json", true, "/a");
    log_with_read(dir.path(), "trace-2.json", true, "/b");
    let accesses = read_traces(dir.path()).unwrap().expect("complete traces");
    assert_eq!(accesses.reads, ["/a".into(), "/b".into()].into());
}

#[test]
fn one_incomplete_launch_makes_the_whole_record_untrusted() {
    let dir = tempfile::tempdir().unwrap();
    log_with_read(dir.path(), "trace-1.json", true, "/a");
    log_with_read(dir.path(), "trace-2.json", false, "/b");
    assert_eq!(read_traces(dir.path()).unwrap(), None);
}

#[test]
fn an_unreadable_or_absent_record_is_no_trace() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(read_traces(dir.path()).unwrap(), None);
    fs::write(dir.path().join("trace-1.json"), "{").unwrap();
    assert_eq!(read_traces(dir.path()).unwrap(), None);
}

#[test]
#[cfg_attr(not(target_os = "linux"), ignore = "file access tracing is implemented for Linux")]
fn the_helper_traces_the_command_and_exits_like_it() {
    let dir = tempfile::tempdir().unwrap();
    let logs = dir.path().join("logs");
    fs::create_dir(&logs).unwrap();
    let input = dir
        .path()
        .canonicalize()
        .unwrap()
        .join("input.txt");
    fs::write(&input, "x").unwrap();
    let mut argv = launcher(Path::new("pnpm"), &logs);
    argv.extend(["sh", "-c", "cat \"$0\" > /dev/null; exit 4"].map(OsString::from));
    argv.push(input.clone().into());
    assert_eq!(try_run(&argv), Some(4));
    let accesses = read_traces(&logs).unwrap().expect("a complete trace");
    assert!(accesses.reads.contains(&input));
}
