use crate::{FileAccesses, Recorder};
use std::{
    fs,
    path::{Path, PathBuf},
    process::ExitStatus,
};

fn record_sh(dir: &Path, script: &str) -> (ExitStatus, Option<FileAccesses>) {
    let recorder = Recorder::new().expect("this system supports recording");
    let mut command = recorder.command("sh".as_ref());
    command
        .args(["-c", script])
        .current_dir(dir);
    let prepared = recorder.prepare(&mut command).expect("prepare the command");
    let mut child = command.spawn().expect("run the command");
    prepared.started(&child);
    let status = child.wait().expect("wait for the command");
    let accesses = recorder.finish();
    dbg!(&accesses);
    (status, accesses)
}

fn recorded(dir: &Path, script: &str) -> FileAccesses {
    let (status, accesses) = record_sh(dir, script);
    assert!(status.success(), "{script} exits cleanly");
    accesses.expect("every access is recorded")
}

fn fixture() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().canonicalize().unwrap();
    (temp, dir)
}

#[test]
fn records_files_read_by_the_system_shell_and_core_utilities() {
    let (_temp, dir) = fixture();
    fs::write(dir.join("input.txt"), "hello").unwrap();
    let accesses = recorded(&dir, "cat input.txt > copy.txt; ls > /dev/null");
    assert!(accesses.reads.contains(&dir.join("input.txt")));
    assert!(accesses.writes.contains(&dir.join("copy.txt")));
    assert!(accesses.listings.contains(&dir));
}

#[test]
fn records_files_node_reads() {
    let (_temp, dir) = fixture();
    fs::write(dir.join("input.txt"), "hello").unwrap();
    let accesses = recorded(
        &dir,
        "node -e \"require('fs').readFileSync('input.txt'); require('fs').existsSync('missing.txt')\"",
    );
    assert!(accesses.reads.contains(&dir.join("input.txt")));
    assert!(accesses.probes.contains(&dir.join("missing.txt")));
}

#[test]
fn a_file_read_then_rewritten_is_a_modified_read() {
    let (_temp, dir) = fixture();
    fs::write(dir.join("config.txt"), "old").unwrap();
    let accesses = recorded(&dir, "cat config.txt > /dev/null; echo new > config.txt");
    assert!(accesses.modified_reads.contains(&dir.join("config.txt")));
}

#[test]
fn a_system_program_without_a_stand_in_makes_the_record_incomplete() {
    let (_temp, dir) = fixture();
    let (status, accesses) = record_sh(
        &dir,
        "/usr/bin/true && /usr/bin/uname > /dev/null && /usr/bin/xattr -h > /dev/null",
    );
    assert!(status.success());
    assert_eq!(accesses, None);
}

#[test]
fn reports_the_exit_status_of_the_command() {
    let (_temp, dir) = fixture();
    let (status, _) = record_sh(&dir, "exit 3");
    assert_eq!(status.code(), Some(3));
}
