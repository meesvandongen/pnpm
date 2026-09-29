use super::parse_release;
use crate::{FileAccesses, PathState, Recorder, Unobserved};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
    time::{Duration, Instant},
};

fn record(mut command: Command) -> (ExitStatus, Result<FileAccesses, Unobserved>) {
    let recorder = Recorder::new().expect("this kernel supports recording");
    let prepared = recorder.prepare(&mut command).expect("prepare the command");
    let mut child = command.spawn().expect("run the command");
    prepared.started(&child);
    let status = child.wait().expect("wait for the command");
    let accesses = recorder.finish();
    dbg!(&accesses);
    (status, accesses)
}

fn record_sh(dir: &Path, script: &str) -> FileAccesses {
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg(script)
        .current_dir(dir);
    let (status, accesses) = record(command);
    assert!(status.success(), "{script} exits cleanly");
    accesses.expect("every access is recorded")
}

fn fixture() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().canonicalize().unwrap();
    (temp, dir)
}

#[test]
fn records_files_read_by_descendants() {
    let (_temp, dir) = fixture();
    fs::write(dir.join("input.txt"), "hello").unwrap();
    let accesses = record_sh(&dir, r#"sh -c "cat input.txt > /dev/null""#);
    assert!(accesses.reads.contains(&dir.join("input.txt")));
}

#[test]
fn records_files_read_by_a_process_whose_parent_exited() {
    let (_temp, dir) = fixture();
    fs::write(dir.join("input.txt"), "hello").unwrap();
    // The inner shell exits at once, so the subshell reads after its parent
    // is gone, while the command still runs.
    let accesses = record_sh(&dir, "sh -c '(sleep 0.5; cat input.txt > /dev/null) &'; sleep 2");
    assert!(accesses.reads.contains(&dir.join("input.txt")));
}

#[test]
fn records_missing_paths_as_probes_and_reads() {
    let (_temp, dir) = fixture();
    let accesses = record_sh(&dir, "test -e missing.txt; cat absent.txt 2>/dev/null; true");
    assert!(accesses.probes.contains(&dir.join("missing.txt")));
    assert!(accesses.reads.contains(&dir.join("absent.txt")));
    assert!(!accesses.observed[&dir.join("absent.txt")].exists());
}

#[test]
fn records_directory_listings() {
    let (_temp, dir) = fixture();
    fs::create_dir(dir.join("src")).unwrap();
    fs::write(dir.join("src/a.txt"), "a").unwrap();
    let accesses = record_sh(&dir, "ls src > /dev/null");
    assert!(accesses.listings.contains(&dir.join("src")));
}

#[test]
fn records_attempted_writes() {
    let (_temp, dir) = fixture();
    fs::write(dir.join("old.txt"), "old").unwrap();
    let accesses = record_sh(
        &dir,
        "echo out > out.txt; mkdir made; mv old.txt new.txt; echo x > no/such/file 2>/dev/null; true",
    );
    for written in ["out.txt", "made", "old.txt", "new.txt", "no/such/file"] {
        assert!(accesses.writes.contains(&dir.join(written)), "{written} was written");
    }
    assert!(accesses.modified_reads.is_empty());
}

#[test]
fn records_executed_programs_as_reads() {
    let (_temp, dir) = fixture();
    // A binary, which no process opens: only `execve` reads it.
    fs::copy(on_path("ls"), dir.join("tool")).unwrap();
    let accesses = record_sh(&dir, "./tool > /dev/null");
    assert!(accesses.reads.contains(&dir.join("tool")));
}

fn on_path(program: &str) -> PathBuf {
    std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| panic!("{program} is on PATH"))
}

#[test]
fn a_file_read_then_rewritten_is_a_modified_read() {
    let (_temp, dir) = fixture();
    fs::write(dir.join("config.txt"), "old").unwrap();
    let accesses = record_sh(
        &dir,
        "cat config.txt > /dev/null; echo new > config.txt; echo made > made.txt; cat made.txt > /dev/null",
    );
    assert_eq!(accesses.modified_reads.iter().collect::<Vec<_>>(), [&dir.join("config.txt")]);
}

#[test]
fn a_file_opened_for_reading_and_writing_is_a_modified_read() {
    let (_temp, dir) = fixture();
    fs::write(dir.join("data.txt"), "old").unwrap();
    let accesses = record_sh(&dir, "exec 3<> data.txt");
    assert!(accesses.modified_reads.contains(&dir.join("data.txt")));
}

#[test]
fn observes_the_state_a_path_had_when_first_accessed() {
    let (_temp, dir) = fixture();
    fs::write(dir.join("input.txt"), "hello").unwrap();
    let accesses = record_sh(&dir, "cat input.txt > /dev/null");
    let observed = accesses.observed[&dir.join("input.txt")];
    assert_eq!(observed, PathState::of(&dir.join("input.txt")));
    fs::write(dir.join("input.txt"), "changed").unwrap();
    assert_ne!(observed, PathState::of(&dir.join("input.txt")));
}

#[test]
fn resolves_paths_against_the_working_directory_of_the_process() {
    let (_temp, dir) = fixture();
    fs::create_dir(dir.join("nested")).unwrap();
    fs::write(dir.join("nested/file.txt"), "x").unwrap();
    let accesses = record_sh(&dir, "cd nested && cat file.txt > /dev/null");
    assert!(accesses.reads.contains(&dir.join("nested/file.txt")));
}

#[test]
fn records_every_prepared_command() {
    let (_temp, dir) = fixture();
    let recorder = Recorder::new().unwrap();
    for file in ["first.txt", "second.txt"] {
        let mut command = Command::new("cat");
        command.arg(dir.join(file));
        let prepared = recorder.prepare(&mut command).unwrap();
        let mut child = command.spawn().unwrap();
        prepared.started(&child);
        child.wait().unwrap();
    }
    let accesses = recorder.finish().expect("every access is recorded");
    assert!(accesses.reads.contains(&dir.join("first.txt")));
    assert!(accesses.reads.contains(&dir.join("second.txt")));
}

#[test]
fn reports_the_exit_status_of_the_command() {
    let (_temp, dir) = fixture();
    let mut command = Command::new("sh");
    command
        .args(["-c", "exit 3"])
        .current_dir(&dir);
    let (status, _) = record(command);
    assert_eq!(status.code(), Some(3));
}

#[test]
fn does_not_wait_for_processes_the_command_leaves_running() {
    let (_temp, dir) = fixture();
    let start = Instant::now();
    record_sh(&dir, "sleep 30 > /dev/null 2>&1 & echo started > started.txt");
    assert!(start.elapsed() < Duration::from_secs(20), "took {:?}", start.elapsed());
}

#[test]
fn io_uring_is_unavailable_to_the_recorded_command() {
    let (_temp, dir) = fixture();
    // `io_uring_setup` is 425 on x86-64 and 64-bit Arm.
    record_sh(&dir, r"perl -e 'exit(syscall(425, 1, 0) == -1 && $!{ENOSYS} ? 0 : 1)'");
}

#[test]
fn threads_of_the_command_are_recorded() {
    let (_temp, dir) = fixture();
    for index in 0..20 {
        fs::write(dir.join(format!("{index}.txt")), "x").unwrap();
    }
    let script = "const fs = require('fs/promises'); \
        Promise.all(Array.from({ length: 20 }, (_, i) => fs.readFile(`${i}.txt`)))";
    let mut command = Command::new("node");
    command
        .args(["-e", script])
        .current_dir(&dir);
    let (status, accesses) = record(command);
    assert!(status.success());
    let accesses = accesses.expect("every access is recorded");
    for index in 0..20 {
        assert!(accesses.reads.contains(&dir.join(format!("{index}.txt"))), "{index}.txt");
    }
}

#[test]
fn a_missing_program_is_a_spawn_error() {
    let recorder = Recorder::new().unwrap();
    let mut command = Command::new("pnpm-fs-access-tracer-no-such-program");
    let prepared = recorder.prepare(&mut command).unwrap();
    let error = command.status().expect_err("the program does not exist");
    drop(prepared);
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn kernel_releases_are_parsed_to_their_major_and_minor_version() {
    assert_eq!(parse_release("6.8.0-45-generic"), Some((6, 8)));
    assert_eq!(parse_release("5.15.167.4-microsoft-standard-WSL2"), Some((5, 15)));
    assert_eq!(parse_release("garbage"), None);
}
