use super::{TaskCache, TrackingScope, written_outputs};
use crate::cli_args::pipeline::cache::FileMatcher;
use pnpm_fs_access_tracer::FileAccesses;
use std::{fs, path::PathBuf};

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    project: PathBuf,
    cache: TaskCache,
}

fn fixture() -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let root = temp
        .path()
        .canonicalize()
        .unwrap()
        .join("workspace");
    let project = root.join("app");
    fs::create_dir_all(project.join("src")).unwrap();
    fs::write(project.join("src/index.js"), "source").unwrap();
    fs::write(root.join("tsconfig.json"), "{}").unwrap();
    let cache = TaskCache::open(&temp.path().join("cache"), &root).unwrap();
    Fixture { _temp: temp, root, project, cache }
}

fn record(fixture: &Fixture, accesses: &FileAccesses) -> String {
    let outputs = FileMatcher::new(&["dist/**"], &[]).unwrap();
    let exclusions = FileMatcher::new(&[], &["src/generated.js"]).unwrap();
    let scope =
        TrackingScope { project_dir: &fixture.project, outputs: &outputs, exclusions: &exclusions };
    fixture.cache.record_tracked_inputs("base", accesses, &scope).unwrap()
}

fn recorded_paths(fixture: &Fixture) -> Vec<String> {
    let text = fs::read_to_string(fixture.cache.tracked_inputs_path("base")).unwrap();
    let record: serde_json::Value = serde_json::from_str(&text).unwrap();
    record["inputs"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect()
}

#[test]
fn an_unrecorded_task_has_no_tracked_key() {
    let fixture = fixture();
    assert_eq!(fixture.cache.tracked_key("base"), None);
}

#[test]
fn the_key_holds_until_a_read_file_changes() {
    let fixture = fixture();
    let mut accesses = FileAccesses::default();
    accesses.reads.insert(fixture.project.join("src/index.js"));
    let key = record(&fixture, &accesses);
    assert_eq!(fixture.cache.tracked_key("base").as_deref(), Some(key.as_str()));
    fs::write(fixture.project.join("src/index.js"), "changed").unwrap();
    assert_ne!(fixture.cache.tracked_key("base").as_deref(), Some(key.as_str()));
    fs::write(fixture.project.join("src/index.js"), "source").unwrap();
    assert_eq!(fixture.cache.tracked_key("base").as_deref(), Some(key.as_str()));
}

#[test]
fn a_probed_path_invalidates_only_when_it_appears_or_disappears() {
    let fixture = fixture();
    let mut accesses = FileAccesses::default();
    accesses.probes.insert(fixture.project.join("src/index.ts"));
    accesses.probes.insert(fixture.project.join("src/index.js"));
    let key = record(&fixture, &accesses);
    fs::write(fixture.project.join("src/index.js"), "changed").unwrap();
    assert_eq!(fixture.cache.tracked_key("base").as_deref(), Some(key.as_str()));
    fs::write(fixture.project.join("src/index.ts"), "typescript").unwrap();
    assert_ne!(fixture.cache.tracked_key("base").as_deref(), Some(key.as_str()));
}

#[test]
fn a_listed_directory_invalidates_when_its_entries_change() {
    let fixture = fixture();
    let mut accesses = FileAccesses::default();
    accesses.listings.insert(fixture.project.join("src"));
    let key = record(&fixture, &accesses);
    fs::write(fixture.project.join("src/index.js"), "changed").unwrap();
    assert_eq!(fixture.cache.tracked_key("base").as_deref(), Some(key.as_str()));
    fs::write(fixture.project.join("src/other.js"), "new").unwrap();
    assert_ne!(fixture.cache.tracked_key("base").as_deref(), Some(key.as_str()));
}

#[test]
fn only_workspace_paths_the_task_did_not_produce_are_inputs() {
    let fixture = fixture();
    let modules = fixture.project.join("node_modules/dep");
    fs::create_dir_all(&modules).unwrap();
    let mut accesses = FileAccesses::default();
    accesses.reads.extend([
        fixture.project.join("src/index.js"),
        fixture.project.join("src/../../tsconfig.json"),
        fixture.project.join("src/generated.js"),
        fixture.project.join("dist/index.js"),
        fixture.project.join("tmp.txt"),
        modules.join("index.js"),
        PathBuf::from("/etc/hostname"),
    ]);
    accesses.writes.insert(fixture.project.join("tmp.txt"));
    record(&fixture, &accesses);
    assert_eq!(recorded_paths(&fixture), ["app/src/index.js", "tsconfig.json"]);
}

#[cfg(unix)]
#[test]
fn a_workspace_dependency_is_recorded_at_its_real_path() {
    let fixture = fixture();
    let lib = fixture.root.join("lib");
    fs::create_dir_all(lib.join("dist")).unwrap();
    fs::write(lib.join("dist/index.js"), "built").unwrap();
    fs::create_dir_all(fixture.project.join("node_modules")).unwrap();
    std::os::unix::fs::symlink(&lib, fixture.project.join("node_modules/lib")).unwrap();
    let mut accesses = FileAccesses::default();
    accesses.reads.insert(fixture.project.join("node_modules/lib/dist/index.js"));
    let key = record(&fixture, &accesses);
    assert_eq!(recorded_paths(&fixture), ["lib/dist/index.js"]);
    fs::write(lib.join("dist/index.js"), "rebuilt").unwrap();
    assert_ne!(fixture.cache.tracked_key("base").as_deref(), Some(key.as_str()));
}

#[test]
fn a_different_access_to_the_same_path_keeps_the_strongest() {
    let fixture = fixture();
    let mut accesses = FileAccesses::default();
    accesses.probes.insert(fixture.project.join("src/index.js"));
    accesses.reads.insert(fixture.project.join("src/index.js"));
    let key = record(&fixture, &accesses);
    fs::write(fixture.project.join("src/index.js"), "changed").unwrap();
    assert_ne!(fixture.cache.tracked_key("base").as_deref(), Some(key.as_str()));
}

#[test]
fn written_outputs_are_the_project_files_the_task_left_behind() {
    let fixture = fixture();
    fs::create_dir_all(fixture.project.join("dist")).unwrap();
    fs::write(fixture.project.join("dist/index.js"), "built").unwrap();
    fs::write(fixture.project.join("dist/index.js.map"), "map").unwrap();
    let mut accesses = FileAccesses::default();
    accesses.writes.extend([
        fixture.project.join("dist"),
        fixture.project.join("dist/index.js"),
        fixture.project.join("dist/index.js.map"),
        fixture.project.join("dist/deleted.tmp"),
        fixture.project.join("node_modules/.cache/state"),
        fixture.root.join("outside.txt"),
    ]);
    let exclusions = FileMatcher::new(&[], &["**/*.map"]).unwrap();
    assert_eq!(written_outputs(&accesses, &fixture.project, &exclusions), ["dist/index.js"],);
}
