//! Reading back the access logs that hook libraries write inside a
//! recorded process tree (see [`pnpm_fs_access_protocol`]).

use crate::FileAccesses;
use pnpm_fs_access_protocol::{Event, Record, decode_all, native_path};
use std::{collections::HashMap, fs, io, path::Path};

/// The accesses every log in `dir` records, or `None` when some process of
/// the tree ran without the hook: a log was cut short, a created process
/// never started the hook, or an `exec` neither failed nor started it.
pub(crate) fn read_logs(dir: &Path) -> io::Result<Option<FileAccesses>> {
    let mut contents = Vec::new();
    for entry in fs::read_dir(dir)? {
        contents.push(fs::read(entry?.path())?);
    }
    let mut records: Vec<Record<'_>> = Vec::new();
    for log in &contents {
        match decode_all(log) {
            Ok(decoded) => records.extend(decoded),
            Err(_) => return Ok(None),
        }
    }
    records.sort_by_key(|record| record.time);
    if !every_process_began(&records) {
        return Ok(None);
    }
    let mut accesses = FileAccesses::default();
    for record in &records {
        if let Event::Accessed { access, state, path } = record.event {
            let path = native_path(path);
            accesses.note(access, &path, || state.unwrap_or_else(|| crate::PathState::of(&path)));
        }
    }
    Ok(Some(accesses))
}

/// Whether every process the records create or `exec` also began the
/// hook, which is what makes its accesses part of the record.
fn every_process_began(records: &[Record<'_>]) -> bool {
    let mut began: HashMap<u32, Vec<u64>> = HashMap::new();
    for record in records {
        if let Event::Began { .. } = record.event {
            began
                .entry(record.pid)
                .or_default()
                .push(record.time);
        }
    }
    let began_after = |pid: u32, time: u64| {
        began
            .get(&pid)
            .is_some_and(|times| times.iter().any(|began| *began > time))
    };
    // The records are in time order, so a process's last `exec` is the
    // one that decides.
    let mut pending_exec: HashMap<u32, u64> = HashMap::new();
    for record in records {
        match record.event {
            Event::Spawned { child, .. } if !began.contains_key(&child) => return false,
            Event::Executing { .. } => {
                pending_exec.insert(record.pid, record.time);
            }
            Event::ExecFailed => {
                pending_exec.remove(&record.pid);
            }
            Event::Unrecorded => return false,
            _ => {}
        }
    }
    pending_exec.into_iter().all(|(pid, time)| began_after(pid, time))
}

#[cfg(test)]
mod tests;
