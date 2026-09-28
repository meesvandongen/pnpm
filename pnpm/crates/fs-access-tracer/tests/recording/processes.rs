use super::{contains, fixture, node, normalized, observed};
use pnpm_fs_access_tracer::Recorder;
use std::fs;

#[test]
fn a_program_that_does_not_exist_is_an_input() {
    let (_temp, dir) = fixture();
    let accesses = node(&dir, "child_process.spawnSync('./not-there', { stdio: 'ignore' })");
    // Windows looks the name up with each executable extension appended.
    let missing = normalized(&dir.join("not-there"));
    assert!(
        accesses.reads
            .iter()
            .chain(&accesses.probes)
            .any(|path| normalized(path).starts_with(&missing)),
    );
}

#[test]
fn a_command_that_cannot_start_in_its_directory_is_a_spawn_error() {
    let (_temp, dir) = fixture();
    let recorder = Recorder::new().unwrap();
    let mut command = recorder.command("node".as_ref());
    command
        .args(["-e", ""])
        .current_dir(dir.join("missing"));
    let prepared = recorder.prepare(&mut command).unwrap();
    let error = command.spawn().expect_err("the working directory does not exist");
    drop(prepared);
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    let _ = recorder.finish();
}

#[cfg(unix)]
#[test]
fn a_script_started_through_its_shebang_line_is_recorded() {
    use std::os::unix::fs::PermissionsExt;
    let (_temp, dir) = fixture();
    fs::write(dir.join("input.txt"), "x").unwrap();
    let script = dir.join("script.sh");
    fs::write(&script, "#!/bin/sh\ncat input.txt > /dev/null\n").unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    let accesses = node(&dir, "child_process.execFileSync('./script.sh')");
    assert!(contains(&accesses.reads, &script));
    assert!(contains(&accesses.reads, &dir.join("input.txt")));
}

#[test]
fn a_rust_program_is_recorded_completely() {
    let (_temp, dir) = fixture();
    fs::create_dir(dir.join("dir")).unwrap();
    fs::write(dir.join("dir").join("a.txt"), "a").unwrap();
    fs::write(dir.join("stat.txt"), "x").unwrap();
    fs::write(dir.join("read.txt"), "x").unwrap();
    let accesses =
        super::helper::record_scenario(&dir, "rust std").expect("every access is recorded");
    assert!(observed(&accesses, &dir.join("stat.txt")));
    assert!(contains(&accesses.reads, &dir.join("read.txt")));
    assert!(contains(&accesses.listings, &dir.join("dir")));
    assert!(contains(&accesses.writes, &dir.join("written.txt")));
}

#[cfg(target_os = "linux")]
#[test]
fn system_calls_made_without_libc_are_recorded() {
    let (_temp, dir) = fixture();
    fs::create_dir(dir.join("raw-dir")).unwrap();
    fs::write(dir.join("raw-stat.txt"), "x").unwrap();
    let accesses =
        super::helper::record_scenario(&dir, "raw system calls").expect("every access is recorded");
    assert!(contains(&accesses.reads, &dir.join("raw-read.txt")));
    assert!(contains(&accesses.reads, &dir.join("raw-openat2.txt")));
    assert!(observed(&accesses, &dir.join("raw-stat.txt")));
    assert!(contains(&accesses.listings, &dir.join("raw-dir")));
}

#[cfg(windows)]
#[test]
fn programs_started_through_create_process_a_and_w_are_inputs() {
    use std::path::Path;
    let (_temp, dir) = fixture();
    let accesses =
        super::helper::record_scenario(&dir, "create process").expect("every access is recorded");
    for program in
        [r"C:\pnpm_fs_access_no_such_program_a.exe", r"C:\pnpm_fs_access_no_such_program_w.exe"]
    {
        assert!(observed(&accesses, Path::new(program)), "{program}");
    }
}
