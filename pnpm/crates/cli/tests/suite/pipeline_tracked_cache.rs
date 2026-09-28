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
        Workspace::with_files(|dir| {
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
        })
    }

    /// A Git work tree with a root `package.json`, installed once `write`
    /// has added the workspace manifest and the projects.
    fn with_files(write: impl FnOnce(&Path)) -> Self {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path();
        pnpm_testing_utils::git_repo::init_isolated_repo(dir);
        fs::write(dir.join(".gitignore"), "node_modules/\ndist/\n.env.local\n").unwrap();
        fs::write(dir.join("package.json"), r#"{"name":"root","private":true}"#).unwrap();
        write(dir);
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
        self.run_pipeline_with_output().0
    }

    fn run_pipeline_with_output(&self) -> (Vec<&'static str>, String) {
        self.run_configured_pipeline(|_| {})
    }

    fn run_configured_pipeline(
        &self,
        configure: impl FnOnce(&mut Command),
    ) -> (Vec<&'static str>, String) {
        let mut command = self.pnpm();
        command.args(["pipeline", "--full"]);
        configure(&mut command);
        let result = command.assert().success();
        let output = String::from_utf8_lossy(&result.get_output().stdout).into_owned();
        (cache_hits(&output), output)
    }

    fn write(&self, path: &str, contents: &str) {
        fs::write(self.root.path().join(path), contents).unwrap();
    }

    fn read(&self, path: &str) -> String {
        fs::read_to_string(self.root.path().join(path)).unwrap()
    }
}

/// The projects whose `build` the run report of the pipeline that printed
/// `output` says was restored from cache.
fn cache_hits(output: &str) -> Vec<&'static str> {
    let hits = restored_tasks(output);
    ["lib", "app"]
        .into_iter()
        .filter(|project| hits.contains(&format!("{project}#build")))
        .collect()
}

/// The tasks the run report of the pipeline that printed `output` says
/// were restored from cache.
fn restored_tasks(output: &str) -> Vec<String> {
    eprintln!("{output}");
    assert!(!output.contains("not every file access"), "{output}");
    let report_dir = output
        .lines()
        .find_map(|line| line.strip_prefix("Report: "))
        .expect("the pipeline names its report");
    let events = fs::read_to_string(Path::new(report_dir).join("events.ndjson")).unwrap();
    events
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .filter(|event| event["event"] == "taskFinished" && event["cache"] == "hit")
        .map(|event| {
            event["task"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect()
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
fn tracked_outputs_are_restored_from_the_cache() {
    let workspace = Workspace::new();
    assert_eq!(workspace.run_pipeline(), Vec::<&str>::new());
    fs::remove_dir_all(workspace.root.path().join("app/dist")).unwrap();
    assert_eq!(workspace.run_pipeline(), ["lib", "app"]);
    assert_eq!(workspace.read("app/dist/out.txt"), "app-source+lib-source+-");
}

#[test]
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

#[test]
fn a_task_that_rewrites_an_input_is_not_cached() {
    let rewrite = "if (require('fs').existsSync('main.txt')) \
        require('fs').writeFileSync('main.txt', require('fs').readFileSync('main.txt'));\n";
    let workspace = Workspace::new();
    workspace.write("build.js", &format!("{rewrite}{BUILD_SCRIPT}"));
    assert_eq!(workspace.run_pipeline(), Vec::<&str>::new());
    let (hits, output) = workspace.run_pipeline_with_output();
    assert_eq!(hits, ["lib"]);
    assert!(output.contains("the task changed app/main.txt after reading it"), "{output}");

    // Excluded from the inputs, the file no longer stops caching. The
    // changed `inputs` are part of every task's key.
    workspace.write(
        "pnpm-workspace.yaml",
        &WORKSPACE_YAML.replace("'!local.log'", "'!local.log', '!main.txt'"),
    );
    assert_eq!(workspace.run_pipeline(), Vec::<&str>::new());
    assert_eq!(workspace.run_pipeline(), ["lib", "app"]);
}

#[test]
fn an_input_changed_while_the_task_runs_is_not_cached() {
    let pause = r"
const pause = process.env.PIPELINE_TEST_PAUSE;
if (pause && process.argv.includes('main.txt')) {
  require('fs').writeFileSync(require('path').join(pause, 'ready'), '');
  while (!require('fs').existsSync(require('path').join(pause, 'go'))) {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);
  }
}
";
    let workspace = Workspace::new();
    // Pause after reading the inputs, before writing the output.
    workspace.write(
        "build.js",
        &BUILD_SCRIPT.replace("fs.mkdirSync", &format!("{pause}\nfs.mkdirSync")),
    );
    let pause_dir = tempfile::tempdir().unwrap();
    let mut pipeline = workspace.pnpm();
    pipeline
        .args(["pipeline", "--full"])
        .env("PIPELINE_TEST_PAUSE", pause_dir.path())
        .stdout(std::process::Stdio::piped());
    let running = pipeline.spawn().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_mins(2);
    while !pause_dir.path().join("ready").exists() {
        assert!(std::time::Instant::now() < deadline, "the build never paused");
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    workspace.write("app/main.txt", "app-edited");
    fs::write(pause_dir.path().join("go"), "").unwrap();
    let finished = running.wait_with_output().unwrap();
    assert!(finished.status.success());
    let output = String::from_utf8_lossy(&finished.stdout).into_owned();
    assert!(output.contains("app/main.txt changed while the task ran"), "{output}");

    assert_eq!(workspace.run_pipeline(), ["lib"]);
    assert_eq!(workspace.read("app/dist/out.txt"), "app-edited+lib-source+-");
    assert_eq!(workspace.run_pipeline(), ["lib", "app"]);
}

#[test]
fn a_file_added_to_a_listed_directory_invalidates() {
    let workspace = Workspace::new();
    workspace.write(
        "build.js",
        &format!(
            "{BUILD_SCRIPT}if (fs.existsSync('src')) \
             fs.appendFileSync('dist/out.txt', '+' + fs.readdirSync('src').sort().join(','));\n"
        ),
    );
    fs::create_dir(workspace.root.path().join("lib/src")).unwrap();
    workspace.write("lib/src/a.txt", "a");
    assert_eq!(workspace.run_pipeline(), Vec::<&str>::new());
    assert_eq!(workspace.run_pipeline(), ["lib", "app"]);
    workspace.write("lib/src/b.txt", "b");
    assert_eq!(workspace.run_pipeline(), Vec::<&str>::new());
    assert_eq!(workspace.read("lib/dist/out.txt"), "lib-source+-+a.txt,b.txt");
}

#[test]
fn an_input_glob_beside_auto_adds_files_the_task_never_reads() {
    let workspace = Workspace::with_manifest(&WORKSPACE_YAML.replace(
        "'!local.log'",
        "'config/**', '!local.log'",
    ));
    fs::create_dir(workspace.root.path().join("lib/config")).unwrap();
    workspace.write("lib/config/settings.json", "{}");
    assert_eq!(workspace.run_pipeline(), Vec::<&str>::new());
    assert_eq!(workspace.run_pipeline(), ["lib", "app"]);
    workspace.write("lib/config/settings.json", r#"{"changed":true}"#);
    assert!(!workspace.run_pipeline().contains(&"lib"));
}

#[test]
fn a_project_whose_directory_name_is_a_glob_pattern_is_cached() {
    let workspace = Workspace::with_files(|dir| {
        let manifest = WORKSPACE_YAML.replace("packages: [lib, app]", "packages: ['packages/*']");
        fs::write(dir.join("pnpm-workspace.yaml"), manifest).unwrap();
        fs::create_dir(dir.join("packages")).unwrap();
        fs::write(dir.join("packages/build.js"), BUILD_SCRIPT).unwrap();
        write_project(&dir.join("packages/[lib]"), "lib", "", "src.txt");
        fs::write(dir.join("packages/[lib]/src.txt"), "lib-source").unwrap();
    });
    let restored = || restored_tasks(&workspace.run_pipeline_with_output().1);
    assert_eq!(restored(), Vec::<String>::new());
    assert_eq!(restored(), ["packages/[lib]#build"]);
    workspace.write("packages/[lib]/src.txt", "lib-changed");
    assert_eq!(restored(), Vec::<String>::new());
    assert_eq!(workspace.read("packages/[lib]/dist/out.txt"), "lib-changed");
}

#[test]
fn a_script_run_through_a_dependency_s_bin_shim_is_recorded() {
    let workspace = Workspace::with_files(|dir| {
        fs::write(dir.join("pnpm-workspace.yaml"), WORKSPACE_YAML).unwrap();
        fs::create_dir_all(dir.join("lib")).unwrap();
        fs::write(
            dir.join("lib/package.json"),
            r#"{"name":"lib","version":"1.0.0","bin":{"lib-tool":"tool.js"}}"#,
        )
        .unwrap();
        fs::write(dir.join("lib/tool.js"), format!("#!/usr/bin/env node\n{BUILD_SCRIPT}")).unwrap();
        fs::create_dir_all(dir.join("app")).unwrap();
        fs::write(
            dir.join("app/package.json"),
            r#"{"name":"app","version":"1.0.0","scripts":{"build":"lib-tool main.txt"},"dependencies":{"lib":"workspace:*"}}"#,
        )
        .unwrap();
        fs::write(dir.join("app/main.txt"), "app-source").unwrap();
    });
    assert_eq!(workspace.run_pipeline(), Vec::<&str>::new());
    assert_eq!(workspace.read("app/dist/out.txt"), "app-source");
    assert_eq!(workspace.run_pipeline(), ["app"]);
    workspace.write("app/main.txt", "app-changed");
    assert_eq!(workspace.run_pipeline(), Vec::<&str>::new());
    workspace.write("lib/tool.js", &format!("#!/usr/bin/env node\n{BUILD_SCRIPT}// changed\n"));
    assert_eq!(workspace.run_pipeline(), Vec::<&str>::new());
}

#[test]
fn node_writing_its_compile_cache_outside_the_workspace_keeps_tasks_cached() {
    let workspace = Workspace::new();
    let compile_cache = tempfile::tempdir().unwrap();
    let run = || {
        workspace.run_configured_pipeline(|command| {
            command.env("NODE_COMPILE_CACHE", compile_cache.path());
        })
        .0
    };
    assert_eq!(run(), Vec::<&str>::new());
    assert!(
        fs::read_dir(compile_cache.path())
            .unwrap()
            .next()
            .is_some(),
        "node wrote its cache"
    );
    assert_eq!(run(), ["lib", "app"]);
}

#[cfg(windows)]
#[test]
fn a_powershell_script_is_recorded() {
    let workspace = Workspace::with_files(|dir| {
        fs::write(dir.join("pnpm-workspace.yaml"), WORKSPACE_YAML).unwrap();
        fs::write(
            dir.join("build.ps1"),
            "$ErrorActionPreference = 'Stop'\n\
             Write-Output \"building in $((Get-Location).Path)\"\n\
             $text = Get-Content -Raw src.txt\n\
             New-Item -ItemType Directory -Force dist | Out-Null\n\
             Set-Content -NoNewline dist/out.txt $text\n",
        )
        .unwrap();
        fs::create_dir_all(dir.join("lib")).unwrap();
        fs::write(
            dir.join("lib/package.json"),
            r#"{"name":"lib","version":"1.0.0","scripts":{"build":"powershell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ../build.ps1"}}"#,
        )
        .unwrap();
        fs::write(dir.join("lib/src.txt"), "lib-source").unwrap();
    });
    assert_eq!(workspace.run_pipeline(), Vec::<&str>::new());
    assert_eq!(workspace.read("lib/dist/out.txt"), "lib-source");
    assert_eq!(workspace.run_pipeline(), ["lib"]);
    workspace.write("lib/src.txt", "lib-changed");
    assert_eq!(workspace.run_pipeline(), Vec::<&str>::new());
    assert_eq!(workspace.read("lib/dist/out.txt"), "lib-changed");
}
