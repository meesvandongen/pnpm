//! Cache keys for tasks with `inputs: [{ auto: true }]`. Their inputs are
//! not known before they run: the tracer records what a run read, probed,
//! and listed, and the paths inside the workspace become the inputs. A run
//! is stored under its base key (everything but those files) combined with
//! the fingerprints the inputs had. The next run fingerprints the paths
//! of the recent runs again and looks those combinations up, so a change
//! to what a run depended on is a miss for that run's result.

use super::{TaskCache, create_hex_hash, patterns::FileMatcher};
use derive_more::Display;
use pnpm_fs_access_tracer::{FileAccesses, PathState};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    ffi::OsStr,
    fs, io,
    path::{Component, Path, PathBuf},
};

mod fingerprint;
mod name_pattern;

use fingerprint::fingerprint;

const TRACKED_INPUTS_VERSION: u32 = 2;

/// How many of a task's most recent input sets its record keeps. The inputs
/// a run uses can differ from the previous run's: a changed script can
/// read or probe other files. A workspace put back in an earlier state is
/// then found under the input set of the run that last saw that state.
const RECORDED_INPUT_SETS: usize = 8;

/// How a run used an input, which decides what its fingerprint covers: the
/// contents of a file read, the entries of a directory listed, the entries
/// matching a Windows directory query's pattern (the input's last path
/// component), and only the kind (or absence) of a path probed.
///
/// A path used in several ways keeps the greatest. A listing outranks a
/// read because only a directory is listed, and a read of a directory, an
/// open of it, covers no more than its kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Access {
    Probe,
    Match,
    Read,
    List,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct TrackedInput {
    access: Access,
    fingerprint: String,
}

/// The record the successful runs of a task leave under its base key: the
/// input sets of the most recent ones, newest first, each keyed by
/// `/`-separated paths relative to the workspace root.
#[derive(Serialize, Deserialize)]
struct TrackedInputs {
    version: u32,
    runs: Vec<BTreeMap<String, Access>>,
}

/// Why a run's result cannot be stored against the inputs it used.
#[derive(Debug, Display)]
pub enum Unrecordable {
    #[display(
        "the task changed {_0} after reading it, so its result is not cached. To cache it, add the \
         file to the task's `outputs` or exclude it from its `inputs` with `!`"
    )]
    ModifiedInput(String),
    #[display("{_0} changed while the task ran, so its result is not cached")]
    ChangedDuringRun(String),
    #[display("recording the inputs of the task: {_0}")]
    Io(io::Error),
}

/// An observed input: how the run used it, and the paths, as the run named
/// them, that resolve to it.
struct ObservedInput {
    access: Access,
    named: Vec<PathBuf>,
}

/// Which observed paths are a task's inputs: those inside the workspace,
/// outside `node_modules` (the lockfile covers dependencies), not written
/// by the run itself, and inside the project only when neither a declared
/// output nor an `inputs` exclusion.
pub struct TrackingScope<'a> {
    pub project_dir: &'a Path,
    pub outputs: &'a FileMatcher<'a>,
    pub exclusions: &'a FileMatcher<'a>,
}

impl TaskCache {
    /// The key the result of the tracked task with `base_key` is stored
    /// under for the workspace as it is now: that of the most recent
    /// recorded input set with a stored result for the inputs' current
    /// state, else that of the most recent set. `None` when no run of the
    /// task was recorded.
    pub fn tracked_key(&self, base_key: &str) -> Option<String> {
        let runs = self.recorded_runs(base_key);
        let mut fingerprints: HashMap<(&str, Access), String> = HashMap::new();
        let mut keys = runs
            .iter()
            .map(|run| {
                let current: BTreeMap<String, TrackedInput> = run
                    .iter()
                    .map(|(path, &access)| {
                        let fingerprint = fingerprints
                            .entry((path.as_str(), access))
                            .or_insert_with(|| fingerprint(&self.canonical_root.join(path), access))
                            .clone();
                        (path.clone(), TrackedInput { access, fingerprint })
                    })
                    .collect();
                tracked_key(base_key, &current)
            });
        let newest = keys.next()?;
        if self.lookup(&newest).is_some() {
            return Some(newest);
        }
        Some(
            keys.find(|key| self.lookup(key).is_some())
                .unwrap_or(newest),
        )
    }

    /// Record the inputs a successful run of the tracked task with
    /// `base_key` used, and return the key its result belongs under.
    ///
    /// A run that modified one of its inputs, or whose inputs something
    /// else changed while it ran, is not recorded: the result would be
    /// stored against contents it was not built from.
    pub fn record_tracked_inputs(
        &self,
        base_key: &str,
        accesses: &FileAccesses,
        scope: &TrackingScope<'_>,
    ) -> Result<String, Unrecordable> {
        let project_dir = canonical(scope.project_dir);
        if let Some(modified) = accesses.modified_reads
            .iter()
            .filter(|path| path.is_absolute())
            .find_map(|path| self.input_relative_path(path, &project_dir, scope))
        {
            return Err(Unrecordable::ModifiedInput(modified));
        }
        let observed = self.observed_inputs(accesses, &project_dir, scope);
        let inputs: BTreeMap<String, TrackedInput> = observed
            .iter()
            .map(|(path, input)| {
                let fingerprint = fingerprint(&self.canonical_root.join(path), input.access);
                (path.clone(), TrackedInput { access: input.access, fingerprint })
            })
            .collect();
        if let Some(changed) = changed_input(accesses, &observed) {
            return Err(Unrecordable::ChangedDuringRun(changed));
        }
        let key = tracked_key(base_key, &inputs);
        let used: BTreeMap<String, Access> = inputs
            .into_iter()
            .map(|(path, input)| (path, input.access))
            .collect();
        let mut runs = self.recorded_runs(base_key);
        runs.retain(|run| *run != used);
        runs.insert(0, used);
        runs.truncate(RECORDED_INPUT_SETS);
        let path = self.tracked_inputs_path(base_key);
        fs::create_dir_all(path.parent().expect("the record has a parent directory"))
            .map_err(Unrecordable::Io)?;
        let record = TrackedInputs { version: TRACKED_INPUTS_VERSION, runs };
        let json = serde_json::to_vec(&record).map_err(|error| Unrecordable::Io(error.into()))?;
        pnpm_fs::write_atomic(&path, &json).map_err(Unrecordable::Io)?;
        Ok(key)
    }

    fn observed_inputs(
        &self,
        accesses: &FileAccesses,
        project_dir: &Path,
        scope: &TrackingScope<'_>,
    ) -> BTreeMap<String, ObservedInput> {
        let written: HashSet<PathBuf> = accesses.writes
            .iter()
            .map(|path| canonical(path))
            .collect();
        let mut inputs: BTreeMap<String, ObservedInput> = BTreeMap::new();
        for (paths, access) in [
            (&accesses.probes, Access::Probe),
            (&accesses.matches, Access::Match),
            (&accesses.listings, Access::List),
            (&accesses.reads, Access::Read),
        ] {
            // A path that is not absolute is relative to a directory of the
            // process that named it, which this process cannot resolve.
            for named in paths.iter().filter(|named| named.is_absolute()) {
                let path = canonical_input(named, access);
                if written.contains(&path) {
                    continue;
                }
                let Some(relative) = self.input_relative_path(&path, project_dir, scope) else {
                    continue;
                };
                let input = inputs
                    .entry(relative)
                    .or_insert(ObservedInput { access, named: Vec::new() });
                input.access = input.access.max(access);
                input.named.push(named.clone());
            }
        }
        inputs
    }

    /// `path` relative to the workspace root when it is one of the task's
    /// inputs.
    fn input_relative_path(
        &self,
        path: &Path,
        project_dir: &Path,
        scope: &TrackingScope<'_>,
    ) -> Option<String> {
        let path = canonical(path);
        self.is_input(&path, project_dir, scope)
            .then(|| relative_slash_path(&path, &self.canonical_root))
            .flatten()
    }

    fn is_input(&self, path: &Path, project_dir: &Path, scope: &TrackingScope<'_>) -> bool {
        let Ok(relative) = path.strip_prefix(&self.canonical_root) else { return false };
        if relative
            .components()
            .any(|component| component.as_os_str() == "node_modules")
        {
            return false;
        }
        match relative_slash_path(path, project_dir) {
            Some(in_project) => {
                !scope.outputs.matches(&in_project) && !scope.exclusions.excludes(&in_project)
            }
            None => true,
        }
    }

    /// The input sets recorded for `base_key`, newest first.
    fn recorded_runs(&self, base_key: &str) -> Vec<BTreeMap<String, Access>> {
        fs::read_to_string(self.tracked_inputs_path(base_key))
            .ok()
            .and_then(|text| serde_json::from_str::<TrackedInputs>(&text).ok())
            .filter(|record| record.version == TRACKED_INPUTS_VERSION)
            .map(|record| record.runs)
            .unwrap_or_default()
    }

    fn tracked_inputs_path(&self, base_key: &str) -> PathBuf {
        self.state_dir
            .join("tracked")
            .join(format!("{base_key}.json"))
    }
}

/// The first input whose state now differs from the one the run saw.
fn changed_input(
    accesses: &FileAccesses,
    observed: &BTreeMap<String, ObservedInput>,
) -> Option<String> {
    let written_into: HashSet<PathBuf> = accesses.writes
        .iter()
        .filter_map(|path| path.parent())
        .map(canonical)
        .collect();
    observed
        .iter()
        .find(|(_, input)| {
            input.named
                .iter()
                .any(|named| has_changed(accesses, named, input.access, &written_into))
        })
        .map(
            |(path, _)| {
                if path.is_empty() { "the workspace root".to_string() } else { path.clone() }
            },
        )
}

/// Whether `named` changed since the run first accessed it, by what its
/// fingerprint covers: a listed directory the run wrote into changed
/// through the run itself, and a probe only sees the kind of entry.
///
/// A matched directory is checked like a probe of it. Its state changes
/// with every entry added, and the entries a task running beside this one
/// writes there rarely match the pattern.
fn has_changed(
    accesses: &FileAccesses,
    named: &Path,
    access: Access,
    written_into: &HashSet<PathBuf>,
) -> bool {
    let Some(seen) = accesses.observed.get(named) else { return false };
    match access {
        Access::List => !written_into.contains(&canonical(named)) && *seen != PathState::of(named),
        Access::Match => {
            let dir = named.parent().unwrap_or(named);
            !seen.same_entry(&PathState::of(dir))
        }
        Access::Read if !seen.is_dir() => *seen != PathState::of(named),
        Access::Read | Access::Probe => !seen.same_entry(&PathState::of(named)),
    }
}

/// The files inside `project_dir` that `accesses` wrote and that are
/// still there, as sorted `/`-separated relative paths, minus the
/// `exclusions`.
pub fn written_outputs(
    accesses: &FileAccesses,
    project_dir: &Path,
    exclusions: &FileMatcher<'_>,
) -> Vec<String> {
    let project_dir = canonical(project_dir);
    let files: BTreeSet<String> = accesses.writes
        .iter()
        .filter(|path| path.is_absolute())
        .filter_map(|path| relative_slash_path(&canonical(path), &project_dir))
        .filter(|relative| !relative.is_empty() && !exclusions.excludes(relative))
        .filter(|relative| !has_managed_component(Path::new(relative)))
        .filter(|relative| {
            fs::symlink_metadata(project_dir.join(relative)).is_ok_and(|meta| meta.is_file())
        })
        .collect();
    files.into_iter().collect()
}

fn tracked_key(base_key: &str, inputs: &BTreeMap<String, TrackedInput>) -> String {
    let mut components = vec!["pnpm-pipeline-tracked:v1".to_string(), base_key.to_string()];
    for (path, input) in inputs {
        components.push(format!("{path}\0{:?}\0{}", input.access, input.fingerprint));
    }
    create_hex_hash(&components.join("\0"))
}

/// `named` with its symlinks resolved. A pattern is not a path, so only
/// its directory is.
fn canonical_input(named: &Path, access: Access) -> PathBuf {
    match (access, named.parent(), named.file_name()) {
        (Access::Match, Some(dir), Some(pattern)) => canonical(dir).join(pattern),
        _ => canonical(named),
    }
}

/// `path` with its symlinks resolved, or normalized as written when it
/// cannot be (a dangling symlink, a path through a file).
fn canonical(path: &Path) -> PathBuf {
    pnpm_fs::realpath_missing(path).unwrap_or_else(|_| pnpm_fs::lexical_normalize(path))
}

fn relative_slash_path(path: &Path, base: &Path) -> Option<String> {
    let relative = path.strip_prefix(base).ok()?;
    let parts: Vec<&OsStr> = relative
        .components()
        .map(Component::as_os_str)
        .collect();
    Some(
        parts
            .iter()
            .map(|part| part.to_string_lossy())
            .collect::<Vec<_>>()
            .join("/"),
    )
}

fn has_managed_component(relative: &Path) -> bool {
    relative
        .components()
        .any(|component| {
            let name = component.as_os_str();
            name.eq_ignore_ascii_case("node_modules") || name.eq_ignore_ascii_case(".git")
        })
}

#[cfg(test)]
mod tests;
