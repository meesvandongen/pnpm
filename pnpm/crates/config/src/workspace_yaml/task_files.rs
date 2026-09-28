use super::TaskSettings;
use serde::Deserialize;

/// One entry of a task's `inputs` or `outputs`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(untagged)]
pub enum TaskFilePattern {
    /// A glob relative to the project directory. A `!` prefix excludes the
    /// files it matches instead.
    Glob(String),
    /// `{ auto: true }`: the files `pnpm pipeline` observes the task
    /// access while it runs.
    Auto(AutoTracking),
}

/// The `{ auto: true }` entry. `{ auto: false }` is accepted and has no
/// effect.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutoTracking {
    pub auto: bool,
}

/// A task's `inputs` or `outputs`, sorted by what each entry does.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TaskFiles<'a> {
    /// Whether an `{ auto: true }` entry is present.
    pub auto: bool,
    /// The glob entries without a `!` prefix, as written.
    pub globs: Vec<&'a str>,
    /// The `!`-prefixed glob entries, with the prefix removed.
    pub exclusions: Vec<&'a str>,
}

impl<'a> TaskFiles<'a> {
    fn new(patterns: &'a [TaskFilePattern]) -> Self {
        let mut files = TaskFiles::default();
        for pattern in patterns {
            match pattern {
                TaskFilePattern::Auto(AutoTracking { auto }) => files.auto |= auto,
                TaskFilePattern::Glob(glob) => match glob.strip_prefix('!') {
                    Some(exclusion) => files.exclusions.push(exclusion),
                    None => files.globs.push(glob),
                },
            }
        }
        files
    }
}

impl TaskSettings {
    /// The task's `inputs`, or `None` when it declares none.
    #[must_use]
    pub fn input_files(&self) -> Option<TaskFiles<'_>> {
        self.inputs.as_deref().map(TaskFiles::new)
    }

    /// The task's `outputs`, or `None` when it declares none.
    #[must_use]
    pub fn output_files(&self) -> Option<TaskFiles<'_>> {
        self.outputs.as_deref().map(TaskFiles::new)
    }
}

#[cfg(test)]
mod tests;
