use std::{fs, io, path::Path, time::SystemTime};

/// What a path was at one moment: missing, or the identity, size, and
/// modification times of what it resolved to. Two states are equal when
/// nothing observable about the path changed in between.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathState(State);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Missing,
    Inaccessible,
    Present(Present),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Present {
    kind: Kind,
    size: u64,
    modified: Option<(i64, u32)>,
    /// Device and inode, and the change time, where the platform has them.
    identity: (u64, u64),
    changed: (i64, i64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Kind {
    File = 0,
    Dir = 1,
    Other = 2,
}

const MISSING: u8 = 0;
const INACCESSIBLE: u8 = 1;
const PRESENT: u8 = 2;

impl PathState {
    /// The number of bytes [`PathState::encode`] writes.
    pub const ENCODED_LEN: usize = 1 + 1 + 8 + 1 + 8 + 4 + 16 + 16;

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
            Err(_) => return PathState(State::Inaccessible),
        };
        let kind = match (metadata.is_file(), metadata.is_dir()) {
            (true, _) => Kind::File,
            (_, true) => Kind::Dir,
            _ => Kind::Other,
        };
        let (identity, changed) = platform_identity(&metadata);
        PathState(State::Present(Present {
            kind,
            size: metadata.len(),
            modified: metadata.modified().ok().map(split_time),
            identity,
            changed,
        }))
    }

    #[must_use]
    pub fn exists(&self) -> bool {
        matches!(self.0, State::Present(_))
    }

    #[must_use]
    pub fn is_dir(&self) -> bool {
        matches!(self.0, State::Present(Present { kind: Kind::Dir, .. }))
    }

    /// Whether both states are missing, or both the same kind of entry,
    /// whatever their contents.
    #[must_use]
    pub fn same_entry(&self, other: &PathState) -> bool {
        match (self.0, other.0) {
            (State::Present(left), State::Present(right)) => left.kind == right.kind,
            (left, right) => left == right,
        }
    }

    /// Write the state into `out`, which holds at least
    /// [`PathState::ENCODED_LEN`] bytes.
    pub fn encode(&self, out: &mut [u8]) {
        out[..Self::ENCODED_LEN].fill(0);
        let present = match self.0 {
            State::Missing => {
                out[0] = MISSING;
                return;
            }
            State::Inaccessible => {
                out[0] = INACCESSIBLE;
                return;
            }
            State::Present(present) => present,
        };
        out[0] = PRESENT;
        out[1] = present.kind as u8;
        out[2..10].copy_from_slice(&present.size.to_le_bytes());
        if let Some((seconds, nanos)) = present.modified {
            out[10] = 1;
            out[11..19].copy_from_slice(&seconds.to_le_bytes());
            out[19..23].copy_from_slice(&nanos.to_le_bytes());
        }
        out[23..31].copy_from_slice(&present.identity.0.to_le_bytes());
        out[31..39].copy_from_slice(&present.identity.1.to_le_bytes());
        out[39..47].copy_from_slice(&present.changed.0.to_le_bytes());
        out[47..55].copy_from_slice(&present.changed.1.to_le_bytes());
    }

    /// Read a state [`PathState::encode`] wrote, or `None` when the bytes
    /// are not one.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let bytes = bytes.get(..Self::ENCODED_LEN)?;
        let u64_at = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().expect("8 bytes"));
        let i64_at = |at: usize| i64::from_le_bytes(bytes[at..at + 8].try_into().expect("8 bytes"));
        let state = match bytes[0] {
            MISSING => State::Missing,
            INACCESSIBLE => State::Inaccessible,
            PRESENT => State::Present(Present {
                kind: match bytes[1] {
                    0 => Kind::File,
                    1 => Kind::Dir,
                    2 => Kind::Other,
                    _ => return None,
                },
                size: u64_at(2),
                modified: (bytes[10] == 1).then(|| {
                    (i64_at(11), u32::from_le_bytes(bytes[19..23].try_into().expect("4 bytes")))
                }),
                identity: (u64_at(23), u64_at(31)),
                changed: (i64_at(39), i64_at(47)),
            }),
            _ => return None,
        };
        Some(PathState(state))
    }
}

/// A time as whole seconds since the Unix epoch, which may be negative,
/// and the nanoseconds past them.
fn split_time(time: SystemTime) -> (i64, u32) {
    match time.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(after) => (i64::try_from(after.as_secs()).unwrap_or(i64::MAX), after.subsec_nanos()),
        Err(before) => {
            let before = before.duration();
            let seconds = i64::try_from(before.as_secs()).unwrap_or(i64::MAX);
            match before.subsec_nanos() {
                0 => (-seconds, 0),
                nanos => (-seconds - 1, 1_000_000_000 - nanos),
            }
        }
    }
}

#[cfg(unix)]
fn platform_identity(metadata: &fs::Metadata) -> ((u64, u64), (i64, i64)) {
    use std::os::unix::fs::MetadataExt;
    ((metadata.dev(), metadata.ino()), (metadata.ctime(), metadata.ctime_nsec()))
}

/// Windows has no change time, and its file index is not in stable Rust;
/// the creation time stands in for the identity.
#[cfg(windows)]
fn platform_identity(metadata: &fs::Metadata) -> ((u64, u64), (i64, i64)) {
    use std::os::windows::fs::MetadataExt;
    ((metadata.creation_time(), u64::from(metadata.file_attributes())), (0, 0))
}

#[cfg(not(any(unix, windows)))]
fn platform_identity(_: &fs::Metadata) -> ((u64, u64), (i64, i64)) {
    ((0, 0), (0, 0))
}

#[cfg(test)]
mod tests;
