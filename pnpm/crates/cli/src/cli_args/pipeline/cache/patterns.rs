use pnpm_config::{TaskFiles, TaskSettings};
use wax::{Glob, Program};

/// Compiled globs of a task's `inputs` or `outputs`, matched against
/// `/`-separated paths relative to the project directory.
pub(in super::super) struct FileMatcher<'a> {
    globs: Vec<Glob<'a>>,
    exclusions: Vec<Glob<'a>>,
}

impl<'a> FileMatcher<'a> {
    pub(in super::super) fn new(globs: &[&'a str], exclusions: &[&'a str]) -> miette::Result<Self> {
        Ok(FileMatcher { globs: compile_globs(globs)?, exclusions: compile_globs(exclusions)? })
    }

    /// The task's declared outputs.
    pub(in super::super) fn outputs(settings: Option<&'a TaskSettings>) -> miette::Result<Self> {
        let outputs = settings.and_then(TaskSettings::output_files).unwrap_or_default();
        FileMatcher::new(&outputs.globs, &outputs.exclusions)
    }

    pub(in super::super) fn globs(&self) -> &[Glob<'a>] {
        &self.globs
    }

    pub(in super::super) fn excludes(&self, path: &str) -> bool {
        self.exclusions
            .iter()
            .any(|glob| glob.is_match(path))
    }

    /// Matched by a glob and by no exclusion.
    pub(in super::super) fn matches(&self, path: &str) -> bool {
        self.globs
            .iter()
            .any(|glob| glob.is_match(path))
            && !self.excludes(path)
    }
}

/// Which of the project's tracked files a task's `inputs` select.
pub(super) struct InputSelection<'a> {
    auto: bool,
    replace: FileMatcher<'a>,
    add: FileMatcher<'a>,
}

impl<'a> InputSelection<'a> {
    pub(super) fn new(inputs: &TaskFiles<'a>) -> miette::Result<Self> {
        let (add, replace): (Vec<&str>, Vec<&str>) = inputs.globs
            .iter()
            .partition(|glob| glob.starts_with('+'));
        let add: Vec<&str> = add
            .into_iter()
            .map(|glob| &glob[1..])
            .collect();
        Ok(InputSelection {
            auto: inputs.auto,
            replace: FileMatcher::new(&replace, &inputs.exclusions)?,
            add: FileMatcher::new(&add, &[])?,
        })
    }

    /// With automatic tracking, the globs are the only tracked files that
    /// are inputs, so without any the task needs no file list at all.
    pub(super) fn selects_nothing(&self) -> bool {
        self.auto && self.replace.globs.is_empty() && self.add.globs.is_empty()
    }

    pub(super) fn includes(&self, path: &str) -> bool {
        if self.replace.excludes(path) {
            return false;
        }
        let in_default = !self.auto && self.replace.globs.is_empty();
        in_default || self.replace.matches(path) || self.add.matches(path)
    }
}

fn compile_globs<'a>(patterns: &[&'a str]) -> miette::Result<Vec<Glob<'a>>> {
    patterns
        .iter()
        .map(|pattern| {
            Glob::new(pattern).map_err(|error| miette::miette!("invalid glob {pattern:?}: {error}"))
        })
        .collect()
}
