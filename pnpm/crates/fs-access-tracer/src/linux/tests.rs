use super::trace_command;
use crate::Trace;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

fn trace_sh(dir: &Path, script: &str) -> Trace {
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg(script)
        .current_dir(dir);
    let trace = trace_command(command).expect("trace the script");
    dbg!(&trace);
    trace
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
    let trace = trace_sh(&dir, r#"sh -c "cat input.txt > /dev/null""#);
    assert!(trace.complete);
    assert!(trace.status.success());
    assert!(trace.accesses.reads.contains(&dir.join("input.txt")));
}

#[test]
fn records_missing_paths_as_probes_and_reads() {
    let (_temp, dir) = fixture();
    let trace = trace_sh(&dir, "test -e missing.txt; cat absent.txt 2>/dev/null; true");
    assert!(trace.complete);
    assert!(trace.accesses.probes.contains(&dir.join("missing.txt")));
    assert!(trace.accesses.reads.contains(&dir.join("absent.txt")));
}

#[test]
fn records_directory_listings() {
    let (_temp, dir) = fixture();
    fs::create_dir(dir.join("src")).unwrap();
    fs::write(dir.join("src/a.txt"), "a").unwrap();
    let trace = trace_sh(&dir, "ls src > /dev/null");
    assert!(trace.accesses.listings.contains(&dir.join("src")));
}

#[test]
fn records_successful_writes_only() {
    let (_temp, dir) = fixture();
    fs::write(dir.join("old.txt"), "old").unwrap();
    let trace = trace_sh(
        &dir,
        "echo out > out.txt; mkdir made; mv old.txt new.txt; echo x > no/such/file 2>/dev/null; true",
    );
    assert!(trace.complete);
    let writes = &trace.accesses.writes;
    for written in ["out.txt", "made", "old.txt", "new.txt"] {
        assert!(writes.contains(&dir.join(written)), "{written} was written");
    }
    assert!(!writes.contains(&dir.join("no/such/file")));
}

#[test]
fn resolves_paths_against_the_working_directory_of_the_process() {
    let (_temp, dir) = fixture();
    fs::create_dir(dir.join("nested")).unwrap();
    fs::write(dir.join("nested/file.txt"), "x").unwrap();
    let trace = trace_sh(&dir, "cd nested && cat file.txt > /dev/null");
    assert!(trace.accesses.reads.contains(&dir.join("nested/file.txt")));
}

#[test]
fn reports_the_exit_status_of_the_command() {
    let (_temp, dir) = fixture();
    let trace = trace_sh(&dir, "exit 3");
    assert_eq!(trace.status.code(), Some(3));
}

#[test]
fn does_not_wait_for_processes_the_command_leaves_running() {
    let (_temp, dir) = fixture();
    let start = Instant::now();
    let trace = trace_sh(&dir, "sleep 30 > /dev/null 2>&1 & echo started > started.txt");
    assert!(trace.status.success());
    assert!(start.elapsed() < Duration::from_secs(20), "took {:?}", start.elapsed());
}

#[test]
fn io_uring_is_unavailable_to_the_traced_command() {
    let (_temp, dir) = fixture();
    let trace = trace_sh(&dir, r"perl -e 'exit(syscall(425, 1, 0) == -1 && $!{ENOSYS} ? 0 : 1)'");
    assert!(trace.complete);
    assert!(trace.status.success(), "io_uring_setup must fail with ENOSYS");
}

#[test]
fn a_missing_program_is_a_spawn_error() {
    let command = Command::new("pnpm-fs-access-tracer-no-such-program");
    let error = trace_command(command).expect_err("the program does not exist");
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
}
