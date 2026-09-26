use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    path::{Path, PathBuf},
    time::SystemTime,
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
    /// the command ran.
    pub observed: BTreeMap<PathBuf, PathState>,
    /// Files the command read while they existed and wrote afterwards:
    /// inputs it modified.
    pub modified_reads: BTreeSet<PathBuf>,
}

/// What a path was at one moment: missing, or the identity, size, and
/// modification times of what it resolved to. Two states are equal when
/// nothing observable about the path changed in between.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathState(State);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Missing,
    Inaccessible(io::ErrorKind),
    Present {
        kind: Kind,
        size: u64,
        modified: Option<SystemTime>,
        #[cfg(unix)]
        identity: (u64, u64),
        #[cfg(unix)]
        changed: (i64, i64),
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    File,
    Dir,
    Other,
}

impl PathState {
    /// The state of `path` now, following symlinks.
    #[must_use]
    pub fn of(path: &Path) -> Self {
        let metadata = match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) =>
            {
                return PathState(State::Missing);
            }
            Err(error) => return PathState(State::Inaccessible(error.kind())),
        };
        let kind = match (metadata.is_file(), metadata.is_dir()) {
            (true, _) => Kind::File,
            (_, true) => Kind::Dir,
            _ => Kind::Other,
        };
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        PathState(State::Present {
            kind,
            size: metadata.len(),
            modified: metadata.modified().ok(),
            #[cfg(unix)]
            identity: (metadata.dev(), metadata.ino()),
            #[cfg(unix)]
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }

    #[must_use]
    pub fn exists(&self) -> bool {
        matches!(self.0, State::Present { .. })
    }

    #[must_use]
    pub fn is_dir(&self) -> bool {
        matches!(self.0, State::Present { kind: Kind::Dir, .. })
    }

    /// Whether both states are missing, or both the same kind of entry,
    /// whatever their contents.
    #[must_use]
    pub fn same_entry(&self, other: &PathState) -> bool {
        match (self.0, other.0) {
            (State::Present { kind: left, .. }, State::Present { kind: right, .. }) => {
                left == right
            }
            (left, right) => left == right,
        }
    }
}
