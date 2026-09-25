use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::PathBuf};

/// The paths a traced process tree accessed, grouped by how.
///
/// Paths are absolute and as the process named them: relative names are
/// joined onto the working directory or directory descriptor they were
/// resolved against, but symlinks are not resolved and `..` is kept.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileAccesses {
    /// Opened for reading. A path that did not exist is included: the
    /// attempt is what makes the command depend on the path.
    pub reads: BTreeSet<PathBuf>,
    /// Directories whose entries were read.
    pub listings: BTreeSet<PathBuf>,
    /// Checked for existence or metadata without reading contents: `stat`,
    /// `access`, `readlink`, and opens of a directory or an `O_PATH`
    /// descriptor. A path that did not exist is included.
    pub probes: BTreeSet<PathBuf>,
    /// Successfully created, written, truncated, renamed (both the source
    /// and the destination), linked, or removed.
    pub writes: BTreeSet<PathBuf>,
}

impl FileAccesses {
    pub fn extend(&mut self, other: FileAccesses) {
        self.reads.extend(other.reads);
        self.listings.extend(other.listings);
        self.probes.extend(other.probes);
        self.writes.extend(other.writes);
    }
}
