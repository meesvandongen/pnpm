//! Tasks with `{ auto: true }` in their `inputs` or `outputs`: their
//! scripts run under a file access [`Recorder`]. What a run read, probed,
//! and listed inside the workspace becomes the inputs its result is cached
//! against (see [`TrackingScope`] for which paths count), and what it
//! wrote inside its project becomes its outputs.

use super::{
    CacheDisposition, Instant, Status,
    cache::{FileMatcher, TrackingScope, collect_output_files, written_outputs},
    execution::{
        RunTaskOptions, TaskEnvironment, TaskExecution, execute_task_scripts, task_cacheable,
        try_restore,
    },
    outcome::{TaskOutcome, finish_task, store_task, task_warning},
};
use pnpm_config::{Config, TaskSettings};
use pnpm_fs_access_tracer::{FileAccesses, IS_SUPPORTED, Recorder};

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
    let recorder = match recorder(options.config) {
        Ok(recorder) => recorder,
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
    let (execution, accesses) = execute_recorded(options, recorder)?;
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
    let recorder = match recorder(options.config) {
        Ok(recorder) => recorder,
        Err(reason) => {
            task_warning(options, &format!("{reason}, so its result is not cached"));
            return execute_task_scripts(&RunTaskOptions { task_key: None, ..*options });
        }
    };
    let (execution, accesses) = execute_recorded(options, recorder)?;
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

/// A recorder for the task's scripts, or why they cannot be recorded.
fn recorder(config: &Config) -> Result<Recorder, String> {
    if !IS_SUPPORTED {
        return Err("automatic file tracking is not supported on this platform".to_string());
    }
    if config.shell_emulator {
        return Err("automatic file tracking does not support shellEmulator".to_string());
    }
    Recorder::new().map_err(|reason| format!("automatic file tracking is unavailable: {reason}"))
}

/// Run the task's scripts under `recorder`. The accesses are `None` when
/// the scripts failed or were not fully observed.
fn execute_recorded(
    options: &RunTaskOptions<'_, '_>,
    recorder: Recorder,
) -> miette::Result<(TaskExecution, Option<FileAccesses>)> {
    let environment = TaskEnvironment { recorder: Some(&recorder), ..options.environment };
    let execution = execute_task_scripts(&RunTaskOptions { environment, ..*options })?;
    let accesses = recorder.finish();
    if execution.status != Status::Passed {
        return Ok((execution, None));
    }
    if accesses.is_none() {
        task_warning(
            options,
            "not every file access of the task could be observed, so its result is not cached",
        );
    }
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
    let matchers = FileMatcher::outputs(settings)
        .and_then(|outputs| Ok((outputs, FileMatcher::new(&[], &inputs.exclusions)?)));
    let (outputs, exclusions) = match matchers {
        Ok(matchers) => matchers,
        Err(error) => {
            task_warning(options, &format!("recording the inputs of the task: {error}"));
            return None;
        }
    };
    let project_dir = options.node.project.as_path();
    let scope = TrackingScope { project_dir, outputs: &outputs, exclusions: &exclusions };
    options.cache
        .record_tracked_inputs(base_key, accesses, &scope)
        .inspect_err(|error| task_warning(options, &error.to_string()))
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
