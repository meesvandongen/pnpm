use super::{
    ExecutionStatus, IndexMap, IntoDiagnostic, Mutex, Path, PipelineInvocation, PipelineResults,
    Status, TaskCompletion, TaskGraph, TaskKey, TaskNode, Value, format_task,
    render_task_graph_dry_run, task_graph_to_json,
};

pub(super) struct StatusCounts {
    pub(super) failed: usize,
    pub(super) passed: usize,
    pub(super) skipped: usize,
}

impl StatusCounts {
    pub(super) fn of(statuses: &IndexMap<String, ExecutionStatus>) -> Self {
        let count = |wanted: Status| {
            statuses
                .values()
                .filter(|status| status.status == wanted)
                .count()
        };
        StatusCounts {
            failed: count(Status::Failure),
            passed: count(Status::Passed),
            skipped: count(Status::Skipped),
        }
    }
}

/// The selection pre-pass: changed projects since the merge base, plus
/// their transitive dependents. It is an optimization, not the
/// correctness boundary — any doubt about attribution (the merge base
/// cannot be resolved, or the diff touches the workspace root, whose
/// files feed every project) falls through to the full graph.
/// `--dry-run` prints the plan instead of running it.
pub(super) fn print_dry_run(
    invocation: &PipelineInvocation,
    task_graph: &TaskGraph,
    sequenced_tasks: &[TaskKey],
    workspace_root: &Path,
) -> miette::Result<()> {
    if invocation.json {
        let document = task_graph_to_json(task_graph, workspace_root);
        println!("{}", serde_json::to_string_pretty(&document).into_diagnostic()?);
    } else {
        println!("{}", render_task_graph_dry_run(task_graph, sequenced_tasks, workspace_root));
    }
    Ok(())
}

/// Record one task's status. A task that could not run at all aborts the
/// whole pipeline; a task that ran and failed only fails itself, because
/// the pipeline never bails.
pub(super) fn record_task_outcome(
    statuses: &Mutex<IndexMap<String, ExecutionStatus>>,
    abort: &Mutex<Option<miette::Report>>,
    summary_key: &str,
    outcome: miette::Result<ExecutionStatus>,
) -> TaskCompletion {
    let status = match outcome {
        Ok(status) => status,
        Err(error) => {
            abort_with(abort, error);
            return TaskCompletion::Aborted;
        }
    };
    let failed = status.status == Status::Failure;
    statuses.lock().expect("status lock is not poisoned")[summary_key] = status;
    if failed { TaskCompletion::Failed } else { TaskCompletion::Passed }
}

pub(super) fn task_script_bodies(
    node: &TaskNode,
    manifest: &Value,
    enable_pre_post_scripts: bool,
) -> Vec<(String, String)> {
    let mut bodies: Vec<(String, String)> = Vec::new();
    for script in &node.scripts {
        let stages: Vec<String> = if enable_pre_post_scripts {
            vec![format!("pre{script}"), script.clone(), format!("post{script}")]
        } else {
            vec![script.clone()]
        };
        for stage in stages {
            if let Some(body) = manifest
                .get("scripts")
                .and_then(|scripts| scripts.get(&stage))
                .and_then(Value::as_str)
            {
                bodies.push((stage, body.to_string()));
            }
        }
    }
    bodies
}

/// Keep the first error that stops the run.
fn abort_with(abort: &Mutex<Option<miette::Report>>, error: miette::Report) {
    let mut abort = abort.lock().expect("abort slot lock is not poisoned");
    if abort.is_none() {
        *abort = Some(error);
    }
}

impl PipelineResults {
    pub(super) fn abort(&self, error: miette::Report) {
        abort_with(&self.abort, error);
    }

    pub(super) fn new(graph: &TaskGraph, workspace_root: &Path) -> Self {
        Self {
            statuses: Mutex::new(
                graph
                    .keys()
                    .map(|key| (format_task(key, workspace_root), ExecutionStatus::queued()))
                    .collect(),
            ),
            abort: Mutex::new(None),
        }
    }
}
