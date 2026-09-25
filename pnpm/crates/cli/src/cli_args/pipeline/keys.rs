//! Task cache keys. A task's key covers the keys of the tasks it depends
//! on, so keys are computed in dependency order. Most are computed before
//! anything runs, which prices the whole plan up front. A task whose
//! inputs are tracked automatically has no key until it has run or been
//! matched against its recorded inputs, so its key, and the keys of every
//! task downstream of it, are computed as each task starts.

use super::{
    Config, GraphPkg, HashMap, HashSet, Mutex, Path, PathBuf, ProjectGraph, TaskCache, TaskGraph,
    TaskKey, TaskNode, cache, reporting::task_script_bodies, task_environment,
    tracking::tracks_inputs,
};
use pnpm_reporter::{LogEvent, LogLevel, PnpmLog};

/// What computing a key reads.
#[derive(Clone, Copy)]
pub(super) struct KeyContext<'a, 'graph> {
    pub(super) graph: &'a ProjectGraph<GraphPkg<'graph>>,
    pub(super) cache: &'a TaskCache,
    pub(super) config: &'a Config,
    pub(super) emit: fn(&LogEvent),
}

pub(super) struct TaskKeys<'a, 'graph> {
    context: KeyContext<'a, 'graph>,
    /// `false` under `--no-cache`, when no task has a key.
    enabled: bool,
    keys: Mutex<HashMap<TaskKey, Option<String>>>,
    warned_projects: Mutex<HashSet<PathBuf>>,
}

impl<'a, 'graph> TaskKeys<'a, 'graph> {
    /// Compute every key that does not depend on a tracked task, walking
    /// the sequenced order so a task's dependency keys exist when its own
    /// is built.
    pub(super) fn plan(
        context: KeyContext<'a, 'graph>,
        task_graph: &TaskGraph,
        sequenced_tasks: &[TaskKey],
        enabled: bool,
    ) -> miette::Result<Self> {
        let task_keys = TaskKeys {
            context,
            enabled,
            keys: Mutex::new(HashMap::with_capacity(task_graph.len())),
            warned_projects: Mutex::new(HashSet::new()),
        };
        if !enabled {
            return Ok(task_keys);
        }
        for key in sequenced_tasks {
            let node = &task_graph[key];
            if tracks_inputs(context.config.tasks.get(&node.task_name)) {
                continue;
            }
            let Some(dependency_keys) = task_keys.dependency_keys(node) else { continue };
            let task_key = task_keys.compute(node, dependency_keys)?;
            task_keys.settle(key.clone(), task_key);
        }
        Ok(task_keys)
    }

    /// The key of the task `node` is about to run with, computed now when
    /// the plan could not. For a tracked task, this is its base key.
    pub(super) fn key_for(&self, node: &TaskNode) -> miette::Result<Option<String>> {
        if !self.enabled {
            return Ok(None);
        }
        let key = TaskKey { project: node.project.clone(), task_name: node.task_name.clone() };
        if let Some(task_key) = self.lock().get(&key) {
            return Ok(task_key.clone());
        }
        match self.dependency_keys(node) {
            Some(dependency_keys) => self.compute(node, dependency_keys),
            None => Ok(None),
        }
    }

    /// Record the key dependents of the task see.
    pub(super) fn settle(&self, key: TaskKey, task_key: Option<String>) {
        if self.enabled {
            self.lock().insert(key, task_key);
        }
    }

    pub(super) fn into_keys(self) -> HashMap<TaskKey, Option<String>> {
        self.keys.into_inner().expect("task keys lock is not poisoned")
    }

    /// The keys of the tasks `node` depends on, sorted, or `None` when one
    /// is not settled yet. A dependency without a key leaves the task
    /// without one too.
    fn dependency_keys(&self, node: &TaskNode) -> Option<Option<Vec<String>>> {
        let keys = self.lock();
        let mut dependency_keys = Vec::with_capacity(node.dependencies.len());
        for dependency in &node.dependencies {
            match keys.get(dependency)? {
                Some(key) => dependency_keys.push(key.clone()),
                None => return Some(None),
            }
        }
        dependency_keys.sort_unstable();
        Some(Some(dependency_keys))
    }

    fn compute(
        &self,
        node: &TaskNode,
        dependency_keys: Option<Vec<String>>,
    ) -> miette::Result<Option<String>> {
        let Some(dependency_keys) = dependency_keys else { return Ok(None) };
        let context = self.context;
        let manifest = context.graph[node.project.as_path()].package.project
            .manifest
            .value();
        let script_bodies =
            task_script_bodies(node, manifest, context.config.enable_pre_post_scripts);
        let dependency_keys: Vec<&str> = dependency_keys
            .iter()
            .map(String::as_str)
            .collect();
        let task_key = context.cache.compute_task_key(&cache::TaskKeyInputs {
            node,
            settings: context.config.tasks.get(&node.task_name),
            dependency_keys: &dependency_keys,
            script_bodies: &script_bodies,
            environment: &task_environment(
                context.config,
                &node.project,
                &context.config.extra_env_with_node_options(),
            ),
        })?;
        if task_key.is_none() {
            self.warn_without_git_inputs(&node.project);
        }
        Ok(task_key)
    }

    /// Explain a task that runs without a cache key because git cannot
    /// enumerate its project, once per project.
    fn warn_without_git_inputs(&self, project: &Path) {
        let unavailable = self.context.cache.inputs_unavailable(project);
        if !matches!(unavailable, Some(cache::InputsUnavailable::NoGit))
            || !self.warned_projects
                .lock()
                .expect("warned projects lock is not poisoned")
                .insert(project.to_path_buf())
        {
            return;
        }
        (self.context.emit)(&LogEvent::Pnpm(PnpmLog {
            level: LogLevel::Warn,
            message:
                "Cannot enumerate the tracked files of the project with git; running its tasks \
                      without a cache key."
                    .to_string(),
            prefix: project.to_string_lossy().into_owned(),
        }));
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<TaskKey, Option<String>>> {
        self.keys.lock().expect("task keys lock is not poisoned")
    }
}
