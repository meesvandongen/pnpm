//! How a task that ran is settled: its result stored, its status
//! reported, and the key its dependents see.

use super::{
    CacheDisposition, ExecutionStatus, Instant, LogEvent, LogLevel, PnpmLog, Status, capture,
    execution::{RunTaskOptions, TaskExecution},
};

/// How a task settled: its status, and the cache key its dependents see.
pub(super) struct TaskOutcome {
    pub(super) status: ExecutionStatus,
    pub(super) key: Option<String>,
}

/// Store a passed task's result, warning when it cannot be stored.
pub(super) fn store_task(
    options: &RunTaskOptions<'_, '_>,
    cache_key: &str,
    files: std::io::Result<Vec<String>>,
    captured: Vec<capture::CapturedScript>,
) {
    let root = options.node.project.as_path();
    let summary_key = options.reporting.summary_key;
    let stored =
        files.and_then(|files| options.cache.store(cache_key, root, summary_key, files, captured));
    if let Err(error) = stored {
        task_warning(options, &format!("failed to store the task in the cache: {error}"));
    }
}

/// Report a task that ran, and the status it ran to.
pub(super) fn finish_task(
    options: &RunTaskOptions<'_, '_>,
    execution: &TaskExecution,
    disposition: CacheDisposition,
    start: Instant,
) -> ExecutionStatus {
    let root = options.node.project.as_path();
    let duration = start.elapsed().as_secs_f64() * 1e3;
    options.reporting.report.task_finished(
        options.reporting.summary_key,
        execution.status,
        disposition,
        duration,
    );
    ExecutionStatus {
        status: execution.status,
        duration: Some(duration),
        prefix: (execution.status == Status::Failure).then(|| root.to_string_lossy().into_owned()),
        message: execution.message.clone(),
    }
}

pub(super) fn task_warning(options: &RunTaskOptions<'_, '_>, message: &str) {
    (options.reporting.emit)(&LogEvent::Pnpm(PnpmLog {
        level: LogLevel::Warn,
        message: format!("{}: {message}", options.reporting.summary_key),
        prefix: options.node.project.to_string_lossy().into_owned(),
    }));
}
