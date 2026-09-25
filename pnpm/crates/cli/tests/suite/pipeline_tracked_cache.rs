use assert_cmd::prelude::*;
use pnpm_testing_utils::command_env::CommandTestExt;
use std::{fs, path::Path, process::Command};

/// Each project's `build` concatenates the files it names into
/// `dist/out.txt`, reading `lib`'s build through the workspace link.
const BUILD_SCRIPT: &str = r"
const fs = require('fs');
const parts = process.argv.slice(2).map((file) => fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '-');
fs.mkdirSync('dist', { recursive: true });
fs.writeFileSync('dist/out.txt', parts.join('+'));
";

const WORKSPACE_YAML: &str = "packages: [lib, app]
pipelines:
  default: [build]
tasks:
  build:
    dependsOn: ['^build']
    inputs: [{ auto: true }, '!local.log']
    outputs: [{ auto: true }]
";

struct Workspace {
    root: tempfile::TempDir,
    storage: tempfile::TempDir,
}

impl Workspace {
    fn new() -> Self {
        Workspace::with_manifest(WORKSPACE_YAML)
    }

    fn with_manifest(workspace_yaml: &str) -> Self {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path();
        pnpm_testing_utils::git_repo::init_isolated_repo(dir);
        fs::write(dir.join(".gitignore"), "node_modules/\ndist/\n.env.local\n").unwrap();
        fs::write(dir.join("package.json"), r#"{"name":"root","private":true}"#).unwrap();
        fs::write(dir.join("pnpm-workspace.yaml"), workspace_yaml).unwrap();
        fs::write(dir.join("build.js"), BUILD_SCRIPT).unwrap();
        write_project(&dir.join("lib"), "lib", "", "src.txt .env.local");
        write_project(
            &dir.join("app"),
            "app",
            r#","dependencies":{"lib":"workspace:*"}"#,
            "main.txt node_modules/lib/dist/out.txt",
        );
        fs::write(dir.join("lib/src.txt"), "lib-source").unwrap();
        fs::write(dir.join("lib/README.md"), "docs").unwrap();
        fs::write(dir.join("app/main.txt"), "app-source").unwrap();
        let workspace = Workspace { root, storage: tempfile::tempdir().unwrap() };
        workspace
            .pnpm()
            .arg("install")
            .assert()
            .success();
        workspace
    }

    fn pnpm(&self) -> Command {
        let mut command = Command::cargo_bin("pnpm").unwrap().without_ambient_pnpm_config();
        command
            .current_dir(self.root.path())
            .env("XDG_CACHE_HOME", self.storage.path())
            .env("XDG_CONFIG_HOME", self.storage.path().join("config"));
        command
    }

    /// Run the pipeline and return the projects the run report says it
    /// restored from cache.
    fn run_pipeline(&self) -> Vec<&'static str> {
        let result = self
            .pnpm()
            .args(["pipeline", "--full"])
            .assert()
            .success();
        let output = String::from_utf8_lossy(&result.get_output().stdout).into_owned();
        eprintln!("{output}");
        assert!(!output.contains("not every file access"), "{output}");
        let report_dir = output
            .lines()
            .find_map(|line| line.strip_prefix("Report: "))
            .expect("the pipeline names its report");
        let events = fs::read_to_string(Path::new(report_dir).join("events.ndjson")).unwrap();
        let hits: Vec<String> = events
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .filter(|event| event["event"] == "taskFinished" && event["cache"] == "hit")
            .map(|event| {
                event["task"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        ["lib", "app"]
            .into_iter()
            .filter(|project| hits.contains(&format!("{project}#build")))
            .collect()
    }

    fn write(&self, path: &str, contents: &str) {
        fs::write(self.root.path().join(path), contents).unwrap();
    }

    fn read(&self, path: &str) -> String {
        fs::read_to_string(self.root.path().join(path)).unwrap()
    }
}

fn write_project(dir: &Path, name: &str, extra_manifest: &str, files: &str) {
    fs::create_dir_all(dir).unwrap();
    fs::write(
        dir.join("package.json"),
        format!(
            r#"{{"name":"{name}","version":"1.0.0","scripts":{{"build":"node ../build.js {files}"}}{extra_manifest}}}"#
        ),
    )
    .unwrap();
}

#[test]
#[cfg_attr(not(target_os = "linux"), ignore = "file access tracing is implemented for Linux")]
fn tracked_inputs_are_the_files_a_task_reads() {
    let workspace = Workspace::new();
    assert_eq!(workspace.run_pipeline(), Vec::<&str>::new());
    assert_eq!(workspace.read("app/dist/out.txt"), "app-source+lib-source+-");
    assert_eq!(workspace.run_pipeline(), ["lib", "app"]);

    // Neither build reads the README.
    workspace.write("lib/README.md", "more docs");
    assert_eq!(workspace.run_pipeline(), ["lib", "app"]);

    // The Git-ignored file `lib`'s build probed for now exists.
    workspace.write("lib/.env.local", "local");
    assert_eq!(workspace.run_pipeline(), Vec::<&str>::new());
    assert_eq!(workspace.read("app/dist/out.txt"), "app-source+lib-source+local");

    workspace.write("app/main.txt", "app-changed");
    assert_eq!(workspace.run_pipeline(), ["lib"]);
    assert_eq!(workspace.read("app/dist/out.txt"), "app-changed+lib-source+local");
}

#[test]
#[cfg_attr(not(target_os = "linux"), ignore = "file access tracing is implemented for Linux")]
fn tracked_outputs_are_restored_from_the_cache() {
    let workspace = Workspace::new();
    assert_eq!(workspace.run_pipeline(), Vec::<&str>::new());
    fs::remove_dir_all(workspace.root.path().join("app/dist")).unwrap();
    assert_eq!(workspace.run_pipeline(), ["lib", "app"]);
    assert_eq!(workspace.read("app/dist/out.txt"), "app-source+lib-source+-");
}

#[test]
#[cfg_attr(not(target_os = "linux"), ignore = "file access tracing is implemented for Linux")]
fn excluded_inputs_do_not_invalidate() {
    let workspace = Workspace::new();
    fs::write(
        workspace.root.path().join("build.js"),
        format!("if (require('fs').existsSync('local.log')) require('fs').readFileSync('local.log');\n{BUILD_SCRIPT}"),
    )
    .unwrap();
    assert_eq!(workspace.run_pipeline(), Vec::<&str>::new());
    workspace.write("app/local.log", "noise");
    assert_eq!(workspace.run_pipeline(), ["lib", "app"]);
}

#[test]
#[cfg_attr(not(target_os = "linux"), ignore = "file access tracing is implemented for Linux")]
fn tracked_outputs_combine_with_git_based_inputs() {
    let workspace = Workspace::with_manifest(&WORKSPACE_YAML.replace(
        "inputs: [{ auto: true }, '!local.log']",
        "inputs: ['*.txt']",
    ));
    assert_eq!(workspace.run_pipeline(), Vec::<&str>::new());
    fs::remove_dir_all(workspace.root.path().join("lib/dist")).unwrap();
    assert_eq!(workspace.run_pipeline(), ["lib", "app"]);
    assert_eq!(workspace.read("lib/dist/out.txt"), "lib-source+-");
    workspace.write("lib/src.txt", "lib-changed");
    assert_eq!(workspace.run_pipeline(), Vec::<&str>::new());
}
