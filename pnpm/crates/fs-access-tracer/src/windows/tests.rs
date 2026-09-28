use crate::{FileAccesses, Recorder};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::ExitStatus,
};

fn record_cmd(dir: &Path, script: &str) -> (ExitStatus, Option<FileAccesses>) {
    let recorder = Recorder::new().expect("this system supports recording");
    let mut command = recorder.command("cmd.exe".as_ref());
    command
        .args(["/d", "/s", "/c", script])
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
    let (status, accesses) = record_cmd(dir, script);
    assert!(status.success(), "{script} exits cleanly");
    accesses.expect("every access is recorded")
}

/// A path in one spelling, whether the recorder got it from a name the
/// process used (which may have short 8.3 components) or from a handle:
/// canonical where it exists, without a `\\?\` prefix, in any case.
fn normalized(path: &Path) -> String {
    let canonical = fs::canonicalize(path)
        .or_else(|_| {
            let parent = fs::canonicalize(path.parent().unwrap_or(path))?;
            Ok::<_, std::io::Error>(parent.join(path.file_name().unwrap_or_default()))
        })
        .unwrap_or_else(|_| path.to_path_buf());
    let text = canonical.to_string_lossy().to_lowercase();
    text.strip_prefix(r"\\?\")
        .unwrap_or(&text)
        .to_string()
}

fn contains(paths: &BTreeSet<PathBuf>, path: &Path) -> bool {
    paths
        .iter()
        .any(|recorded| normalized(recorded) == normalized(path))
}

fn fixture() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().to_path_buf();
    (temp, dir)
}

#[test]
fn records_files_read_by_descendants() {
    let (_temp, dir) = fixture();
    fs::write(dir.join("input.txt"), "hello").unwrap();
    let accesses = recorded(&dir, "cmd /d /c type input.txt > nul");
    assert!(contains(&accesses.reads, &dir.join("input.txt")));
}

#[test]
fn records_writes_and_listings() {
    let (_temp, dir) = fixture();
    fs::create_dir(dir.join("src")).unwrap();
    fs::write(dir.join("src").join("a.txt"), "a").unwrap();
    let accesses = recorded(&dir, "dir src > nul & echo out> out.txt");
    assert!(contains(&accesses.listings, &dir.join("src")));
    assert!(contains(&accesses.writes, &dir.join("out.txt")));
}

#[test]
fn records_missing_paths_as_probes() {
    let (_temp, dir) = fixture();
    let accesses = recorded(&dir, "if exist missing.txt (echo yes) else (echo no)");
    assert!(contains(&accesses.probes, &dir.join("missing.txt")));
    assert!(!contains(&accesses.listings, &dir));
}

#[test]
fn a_program_search_matches_names_without_listing_the_directory() {
    let (_temp, dir) = fixture();
    let accesses = recorded(&dir, "pnpm-no-such-program 2> nul & exit 0");
    assert!(!contains(&accesses.listings, &dir));
    assert!(
        accesses.matches
            .iter()
            .any(|pattern| {
                pattern
                    .parent()
                    .is_some_and(|parent| normalized(parent) == normalized(&dir))
            })
    );
}

#[test]
fn a_file_read_then_rewritten_is_a_modified_read() {
    let (_temp, dir) = fixture();
    fs::write(dir.join("config.txt"), "old").unwrap();
    let accesses = recorded(&dir, "type config.txt > nul & echo new> config.txt");
    assert!(contains(&accesses.modified_reads, &dir.join("config.txt")));
}

#[test]
fn reports_the_exit_status_of_the_command() {
    let (_temp, dir) = fixture();
    let (status, _) = record_cmd(&dir, "exit 3");
    assert_eq!(status.code(), Some(3));
}
