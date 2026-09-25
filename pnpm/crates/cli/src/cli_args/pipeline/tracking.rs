//! Tasks with `{ auto: true }` in their `inputs` or `outputs`: their
//! scripts run under the file access tracer. What a run read, probed, and
//! listed inside the workspace becomes the inputs its result is cached
//! against (see [`TrackingScope`] for which paths count), and what it
//! wrote inside its project becomes its outputs.

use super::{
    CacheDisposition, Instant, IntoDiagnostic, Status,
    cache::{FileMatcher, TrackingScope, collect_output_files, written_outputs},
    execution::{
        RunTaskOptions, TaskEnvironment, TaskExecution, execute_task_scripts, task_cacheable,
        try_restore,
    },
    outcome::{TaskOutcome, finish_task, store_task, task_warning},
};
use pnpm_config::{Config, TaskSettings};
use pnpm_fs_access_tracer::{FileAccesses, IS_SUPPORTED, helper};
use std::path::{Path, PathBuf};

/// Whether the task's inputs are tracked automatically. A task with
/// `cargoTargetDir` keeps the Git-tracked inputs its Cargo snapshots are
/// keyed on.
pub(super) fn tracks_inputs(settings: Option<&TaskSettings>) -> bool {
    settings.is_some_and(|settings| {
        settings.cargo_target_dir.is_none()
            && settings.input_files().is_some_and(|inputs| inputs.auto)
    })
}

pub(super) fn tracks_outputs(settings: Option<&TaskSettings>) -> bool {
    settings.and_then(TaskSettings::output_files).is_some_and(|outputs| outputs.auto)
}

/// Run a task with tracked inputs: serve it from the cache when the inputs
/// its last recorded run used are unchanged, and otherwise run it under the
/// tracer and record what it used. `options.task_key` is the task's base
/// key.
pub(super) fn run_tracked_task(
    options: &RunTaskOptions<'_, '_>,
    settings: Option<&TaskSettings>,
) -> miette::Result<TaskOutcome> {
    let Some(base_key) = options.task_key else { return run_untracked(options) };
    let executable = match tracer_executable(options.config) {
        Ok(executable) => executable,
        Err(reason) => {
            task_warning(options, &format!("{reason}; running it without the cache"));
            return run_untracked(options);
        }
    };
    let cacheable = task_cacheable(options.invocation, settings);
    let start = Instant::now();
    let lookup_key = cacheable
        .then(|| options.cache.tracked_key(base_key))
        .flatten();
    options.reporting.report.task_started(options.reporting.summary_key, lookup_key.as_deref());
    if let Some(lookup_key) = &lookup_key
        && let Some(status) = try_restore(options, lookup_key, start)?
    {
        return Ok(TaskOutcome { status, key: Some(lookup_key.clone()) });
    }
    let (execution, accesses) = execute_traced(options, &executable)?;
    let key = accesses.and_then(|accesses| {
        let key = record_inputs(options, settings, base_key, &accesses)?;
        if cacheable && let Some(captured) = execution.captured.clone() {
            store_task(options, &key, output_files(options, settings, &accesses), captured);
        }
        Some(key)
    });
    let disposition = if cacheable { CacheDisposition::Miss } else { CacheDisposition::Bypass };
    Ok(TaskOutcome { status: finish_task(options, &execution, disposition, start), key })
}

/// Run a cacheable task with Git-based inputs and tracked outputs, storing
/// its result under `cache_key` when the run was fully observed.
pub(super) fn run_with_tracked_outputs(
    options: &RunTaskOptions<'_, '_>,
    settings: Option<&TaskSettings>,
    cache_key: &str,
) -> miette::Result<TaskExecution> {
    let executable = match tracer_executable(options.config) {
        Ok(executable) => executable,
        Err(reason) => {
            task_warning(options, &format!("{reason}, so its result is not cached"));
            return execute_task_scripts(&RunTaskOptions { task_key: None, ..*options });
        }
    };
    let (execution, accesses) = execute_traced(options, &executable)?;
    if let Some(accesses) = accesses
        && let Some(captured) = execution.captured.clone()
    {
        store_task(options, cache_key, output_files(options, settings, &accesses), captured);
    }
    Ok(execution)
}

/// A tracked task that runs without a cache key, so nothing downstream of
/// it has one either.
fn run_untracked(options: &RunTaskOptions<'_, '_>) -> miette::Result<TaskOutcome> {
    let options = RunTaskOptions { task_key: None, ..*options };
    let start = Instant::now();
    options.reporting.report.task_started(options.reporting.summary_key, None);
    let execution = execute_task_scripts(&options)?;
    let status = finish_task(&options, &execution, CacheDisposition::Bypass, start);
    Ok(TaskOutcome { status, key: None })
}

/// The pnpm executable to run the tracer with, or why the task cannot be
/// traced.
fn tracer_executable(config: &Config) -> Result<PathBuf, &'static str> {
    if !IS_SUPPORTED {
        return Err("automatic file tracking is not supported on this platform");
    }
    if config.shell_emulator {
        return Err("automatic file tracking does not support shellEmulator");
    }
    pnpm_executor::current_pnpm_exe()
        .map_err(|_| "automatic file tracking cannot locate the pnpm executable")
}

/// Run the task's scripts under the tracer. The accesses are `None` when
/// the scripts failed or were not fully observed.
fn execute_traced(
    options: &RunTaskOptions<'_, '_>,
    executable: &Path,
) -> miette::Result<(TaskExecution, Option<FileAccesses>)> {
    let trace_dir = options.cache.trace_dir().into_diagnostic()?;
    let launcher = helper::launcher(executable, trace_dir.path());
    let environment = TaskEnvironment { launcher: &launcher, ..options.environment };
    let execution = execute_task_scripts(&RunTaskOptions { environment, ..*options })?;
    if execution.status != Status::Passed {
        return Ok((execution, None));
    }
    let accesses = match helper::read_traces(trace_dir.path()) {
        Ok(Some(accesses)) => Some(accesses),
        Ok(None) => {
            task_warning(
                options,
                "not every file access of the task could be observed, so its result is not cached",
            );
            None
        }
        Err(error) => {
            task_warning(options, &format!("reading the file accesses of the task: {error}"));
            None
        }
    };
    Ok((execution, accesses))
}

/// Record the inputs a run used, and return the key its result belongs
/// under.
fn record_inputs(
    options: &RunTaskOptions<'_, '_>,
    settings: Option<&TaskSettings>,
    base_key: &str,
    accesses: &FileAccesses,
) -> Option<String> {
    let inputs = settings.and_then(TaskSettings::input_files).unwrap_or_default();
    let recorded = FileMatcher::outputs(settings)
        .and_then(|outputs| {
            let exclusions = FileMatcher::new(&[], &inputs.exclusions)?;
            let project_dir = options.node.project.as_path();
            let scope = TrackingScope { project_dir, outputs: &outputs, exclusions: &exclusions };
            options.cache
                .record_tracked_inputs(base_key, accesses, &scope)
                .map_err(|error| miette::miette!("{error}"))
        });
    recorded
        .inspect_err(|error| {
            task_warning(options, &format!("recording the inputs of the task: {error}"));
        })
        .ok()
}

/// The declared outputs, plus what the run wrote in the project when the
/// outputs include `{ auto: true }`.
fn output_files(
    options: &RunTaskOptions<'_, '_>,
    settings: Option<&TaskSettings>,
    accesses: &FileAccesses,
) -> std::io::Result<Vec<String>> {
    let project_dir = options.node.project.as_path();
    let outputs =
        FileMatcher::outputs(settings).map_err(|error| std::io::Error::other(error.to_string()))?;
    let mut files = collect_output_files(project_dir, &outputs)?;
    if tracks_outputs(settings) {
        files.extend(written_outputs(accesses, project_dir, &outputs));
        files.sort();
        files.dedup();
    }
    Ok(files)
}
