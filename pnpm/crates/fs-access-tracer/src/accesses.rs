use pnpm_fs_access_protocol::{Access, PathState};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

/// The paths a recorded process tree accessed, grouped by how.
///
/// Paths are absolute and as the process named them: relative names are
/// joined onto the working directory or directory descriptor they were
/// resolved against, but symlinks are not resolved and `..` is kept.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FileAccesses {
    /// Opened for reading, or executed. A path that did not exist is
    /// included: the attempt is what makes the command depend on the path.
    pub reads: BTreeSet<PathBuf>,
    /// Directories whose entries were read.
    pub listings: BTreeSet<PathBuf>,
    /// Directories whose entries matching a name pattern were read, as the
    /// directory joined with the pattern. Only Windows queries a directory
    /// by pattern; see `Access::Match` in `pnpm-fs-access-protocol` for the
    /// syntax.
    pub matches: BTreeSet<PathBuf>,
    /// Checked for existence or metadata without reading contents: `stat`,
    /// `access`, `readlink`, and opens of a directory or an `O_PATH`
    /// descriptor. A path that did not exist is included.
    pub probes: BTreeSet<PathBuf>,
    /// Created, opened for writing, truncated, renamed (both the source and
    /// the destination), linked, or removed, whether or not the call
    /// succeeded.
    pub writes: BTreeSet<PathBuf>,
    /// The state each path in `reads`, `listings`, and `probes` had when
    /// the command first accessed it, for telling whether it changed while
    /// the command ran. A path in `matches` has its directory's state.
    pub observed: BTreeMap<PathBuf, PathState>,
    /// Files the command read while they existed and wrote afterwards:
    /// inputs it modified.
    pub modified_reads: BTreeSet<PathBuf>,
}

impl FileAccesses {
    /// Add an access, in the order the process tree made them. `state`
    /// gives the path's state just before the access; it is asked for only
    /// on the first read, probe, or listing of the path.
    pub(crate) fn note(&mut self, access: Access, path: &Path, state: impl FnOnce() -> PathState) {
        let path = clean(path);
        if !matches!(access, Access::Write) && !self.observed.contains_key(&path) {
            self.observed.insert(path.clone(), state());
        }
        match access {
            Access::Read => self.reads.insert(path),
            Access::Probe => self.probes.insert(path),
            Access::List => self.listings.insert(path),
            Access::Match => self.matches.insert(path),
            Access::Write => self.note_write(path),
            Access::ReadWrite => {
                self.reads.insert(path.clone());
                self.note_write(path)
            }
        };
    }

    fn note_write(&mut self, path: PathBuf) -> bool {
        let read_while_present =
            self.reads.contains(&path) && self.observed.get(&path).is_some_and(PathState::exists);
        if read_while_present && !self.writes.contains(&path) {
            self.modified_reads.insert(path.clone());
        }
        self.writes.insert(path)
    }
}

/// `path` without `.` components, repeated separators, or a trailing one.
fn clean(path: &Path) -> PathBuf {
    path.components().collect()
}
