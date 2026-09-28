use crate::PathState;

/// How a process used a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Access {
    /// Opened for reading, or executed.
    Read = 0,
    /// Checked for existence or metadata.
    Probe = 1,
    /// A directory whose entries were read.
    List = 2,
    /// Created, written, renamed, linked, or removed.
    Write = 3,
    /// Opened for both reading and writing without truncating.
    ReadWrite = 4,
    /// The entries of a directory whose names match a pattern were read.
    /// The path is the directory joined with the pattern, in the wildcard
    /// syntax of the Windows directory queries (`*`, `?`, and the DOS
    /// wildcards `<`, `>`, and `"`), none of which a Windows file name can
    /// contain. The state is the directory's.
    Match = 5,
}

/// What a process of the recorded tree did. Paths are native bytes: the
/// path itself on Unix, and its UTF-16 code units, little-endian, on
/// Windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event<'a> {
    /// The hook library started in the process, running `image`: in a new
    /// process, or after `exec`.
    Began { image: &'a [u8] },
    /// The process accessed `path`. `state` is the path's state just
    /// before the access, for the accesses that read it.
    Accessed { access: Access, state: Option<PathState>, path: &'a [u8] },
    /// The process created the process `child`, which is to run `image`.
    Spawned { child: u32, image: &'a [u8] },
    /// The process is about to replace its program with `image`.
    Executing { image: &'a [u8] },
    /// The process's last `exec` failed, so it keeps its program.
    ExecFailed,
    /// The process made an access the hook could not log, so the record
    /// is incomplete.
    Unrecorded,
}

/// One entry of a process's log. `time` comes from a clock that every
/// process of the machine shares, so records of different processes order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record<'a> {
    pub pid: u32,
    pub time: u64,
    pub event: Event<'a>,
}

/// The log ends inside a record: its writer died while writing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Truncated;

/// Length, tag, pid, and time.
pub(crate) const HEADER_LEN: usize = 4 + 1 + 4 + 8;
/// The largest fixed-size part of an event, plus the path length.
pub(crate) const MAX_PAYLOAD_LEN: usize = 1 + 1 + PathState::ENCODED_LEN + 4;

const BEGAN: u8 = 1;
const ACCESSED: u8 = 2;
const SPAWNED: u8 = 3;
const EXECUTING: u8 = 4;
const EXEC_FAILED: u8 = 5;
const UNRECORDED: u8 = 6;

/// Write `record` into `out`, returning its length, or `None` when `out`
/// is too small. Uses no allocation, so a hook may call it between `fork`
/// and `exec`.
pub fn encode(record: &Record<'_>, out: &mut [u8]) -> Option<usize> {
    let mut writer = Writer { out, len: 4 };
    let (tag, path) = match record.event {
        Event::Began { image } => (BEGAN, Some(image)),
        Event::Accessed { path, .. } => (ACCESSED, Some(path)),
        Event::Spawned { image, .. } => (SPAWNED, Some(image)),
        Event::Executing { image } => (EXECUTING, Some(image)),
        Event::ExecFailed => (EXEC_FAILED, None),
        Event::Unrecorded => (UNRECORDED, None),
    };
    writer.put(&[tag])?;
    writer.put(&record.pid.to_le_bytes())?;
    writer.put(&record.time.to_le_bytes())?;
    match record.event {
        Event::Accessed { access, state, .. } => {
            writer.put(&[access as u8, u8::from(state.is_some())])?;
            let mut encoded = [0u8; PathState::ENCODED_LEN];
            if let Some(state) = state {
                state.encode(&mut encoded);
            }
            writer.put(&encoded)?;
        }
        Event::Spawned { child, .. } => writer.put(&child.to_le_bytes())?,
        Event::Began { .. } | Event::Executing { .. } | Event::ExecFailed | Event::Unrecorded => {}
    }
    if let Some(path) = path {
        writer.put(&u32::try_from(path.len()).ok()?.to_le_bytes())?;
        writer.put(path)?;
    }
    let len = writer.len;
    writer.out[..4].copy_from_slice(&u32::try_from(len).ok()?.to_le_bytes());
    Some(len)
}

/// The records in `bytes`, in the order they were written.
pub fn decode_all(bytes: &[u8]) -> Result<Vec<Record<'_>>, Truncated> {
    let mut records = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        let len = rest
            .get(..4)
            .map(|len| u32::from_le_bytes(len.try_into().expect("4 bytes")) as usize)
            .ok_or(Truncated)?;
        let record = rest
            .get(..len)
            .filter(|_| len >= HEADER_LEN)
            .ok_or(Truncated)?;
        records.push(decode(&record[4..]).ok_or(Truncated)?);
        rest = &rest[len..];
    }
    Ok(records)
}

fn decode(bytes: &[u8]) -> Option<Record<'_>> {
    let mut reader = Reader { bytes };
    let tag = reader.take(1)?[0];
    let pid = reader.u32()?;
    let time = u64::from_le_bytes(reader.take(8)?.try_into().ok()?);
    let event = match tag {
        BEGAN => Event::Began { image: reader.path()? },
        ACCESSED => {
            let [access, has_state] = reader.take(2)?.try_into().ok()?;
            let state = reader.take(PathState::ENCODED_LEN)?;
            Event::Accessed {
                access: match access {
                    0 => Access::Read,
                    1 => Access::Probe,
                    2 => Access::List,
                    3 => Access::Write,
                    4 => Access::ReadWrite,
                    5 => Access::Match,
                    _ => return None,
                },
                state: match has_state {
                    0 => None,
                    _ => Some(PathState::decode(state)?),
                },
                path: reader.path()?,
            }
        }
        SPAWNED => Event::Spawned { child: reader.u32()?, image: reader.path()? },
        EXECUTING => Event::Executing { image: reader.path()? },
        EXEC_FAILED => Event::ExecFailed,
        UNRECORDED => Event::Unrecorded,
        _ => return None,
    };
    reader.bytes
        .is_empty()
        .then_some(Record { pid, time, event })
}

struct Writer<'a> {
    out: &'a mut [u8],
    len: usize,
}

impl Writer<'_> {
    fn put(&mut self, bytes: &[u8]) -> Option<()> {
        self.out
            .get_mut(self.len..self.len + bytes.len())?
            .copy_from_slice(bytes);
        self.len += bytes.len();
        Some(())
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let (taken, rest) = self.bytes.split_at_checked(len)?;
        self.bytes = rest;
        Some(taken)
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    fn path(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }
}

#[cfg(test)]
mod tests;
