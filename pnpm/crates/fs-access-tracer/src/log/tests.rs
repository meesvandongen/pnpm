use super::read_logs;
use crate::Unobserved;
use pnpm_fs_access_protocol::{
    Access, Event, PathState, Record, encode, max_record_len, native_bytes, native_path,
};
use std::{fs, path::Path};

fn write_log(dir: &Path, name: &str, records: &[Record<'_>]) {
    let mut log = Vec::new();
    for record in records {
        let mut buffer = vec![0u8; max_record_len(256)];
        let len = encode(record, &mut buffer).unwrap();
        log.extend_from_slice(&buffer[..len]);
    }
    fs::write(dir.join(name), log).unwrap();
}

fn accessed(pid: u32, time: u64, access: Access, path: &[u8]) -> Record<'_> {
    let state = Some(PathState::of(&pnpm_fs_access_protocol::native_path(path)));
    Record { pid, time, event: Event::Accessed { access, state, path } }
}

#[test]
fn the_logs_of_every_process_are_merged_in_time_order() {
    let dir = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let file = workspace.path().join("input.txt");
    fs::write(&file, "x").unwrap();
    let bytes = native_bytes(&file);
    write_log(
        dir.path(),
        "parent.log",
        &[
            Record { pid: 1, time: 1, event: Event::Spawned { child: 2, image: b"/bin/node" } },
            accessed(1, 5, Access::Write, &bytes),
        ],
    );
    write_log(
        dir.path(),
        "child.log",
        &[
            Record { pid: 2, time: 2, event: Event::Began { image: b"/bin/node" } },
            accessed(2, 3, Access::Read, &bytes),
        ],
    );
    let accesses = read_logs(dir.path()).expect("every process began");
    assert!(accesses.reads.contains(&file));
    assert!(accesses.modified_reads.contains(&file), "read by 2, then written by 1");
}

#[test]
fn a_created_process_that_never_began_is_incomplete() {
    let dir = tempfile::tempdir().unwrap();
    write_log(
        dir.path(),
        "parent.log",
        &[Record { pid: 1, time: 1, event: Event::Spawned { child: 2, image: b"/usr/bin/git" } }],
    );
    assert_eq!(read_logs(dir.path()), Err(Unobserved::Program(native_path(b"/usr/bin/git"))));
}

#[test]
fn an_exec_must_fail_or_begin_the_hook_again() {
    let dir = tempfile::tempdir().unwrap();
    let executing = |time| Record { pid: 1, time, event: Event::Executing { image: b"/bin/x" } };
    write_log(
        dir.path(),
        "a.log",
        &[
            executing(1),
            Record { pid: 1, time: 2, event: Event::ExecFailed },
            executing(3),
            Record { pid: 1, time: 4, event: Event::Began { image: b"/bin/x" } },
        ],
    );
    assert!(read_logs(dir.path()).is_ok());
    write_log(dir.path(), "b.log", &[executing(5)]);
    assert_eq!(read_logs(dir.path()), Err(Unobserved::Program(native_path(b"/bin/x"))));
}

#[test]
fn a_cut_log_is_incomplete() {
    let dir = tempfile::tempdir().unwrap();
    write_log(
        dir.path(),
        "a.log",
        &[Record { pid: 1, time: 1, event: Event::Began { image: b"/x" } }],
    );
    let log = fs::read(dir.path().join("a.log")).unwrap();
    fs::write(dir.path().join("a.log"), &log[..log.len() - 1]).unwrap();
    assert_eq!(read_logs(dir.path()), Err(Unobserved::Log));
}
