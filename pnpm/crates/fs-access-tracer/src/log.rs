//! Reading back the access logs that hook libraries write inside a
//! recorded process tree (see [`pnpm_fs_access_protocol`]).

use crate::{FileAccesses, Unobserved};
use pnpm_fs_access_protocol::{Event, Record, decode_all, native_path};
use std::{collections::HashMap, fs, io, path::Path};

/// The accesses every log in `dir` records, or why some process of the
/// tree ran without the hook: a log was cut short, a created process never
/// started the hook, or an `exec` neither failed nor started it.
pub(crate) fn read_logs(dir: &Path) -> Result<FileAccesses, Unobserved> {
    let contents = read_all(dir).map_err(|_| Unobserved::Log)?;
    let mut records: Vec<Record<'_>> = Vec::new();
    for log in &contents {
        records.extend(decode_all(log).map_err(|_| Unobserved::Log)?);
    }
    records.sort_by_key(|record| record.time);
    every_process_began(&records)?;
    let mut accesses = FileAccesses::default();
    for record in &records {
        if let Event::Accessed { access, state, path } = record.event {
            let path = native_path(path);
            accesses.note(access, &path, || state.unwrap_or_else(|| crate::PathState::of(&path)));
        }
    }
    Ok(accesses)
}

fn read_all(dir: &Path) -> io::Result<Vec<Vec<u8>>> {
    fs::read_dir(dir)?
        .map(|entry| fs::read(entry?.path()))
        .collect()
}

/// Check that every process the records create or `exec` also began the
/// hook, which is what makes its accesses part of the record.
fn every_process_began(records: &[Record<'_>]) -> Result<(), Unobserved> {
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
    let mut pending_exec: HashMap<u32, (u64, &[u8])> = HashMap::new();
    for record in records {
        match record.event {
            Event::Spawned { child, image } if !began.contains_key(&child) => {
                return Err(Unobserved::Program(native_path(image)));
            }
            Event::Executing { image } => {
                pending_exec.insert(record.pid, (record.time, image));
            }
            Event::ExecFailed => {
                pending_exec.remove(&record.pid);
            }
            Event::Unrecorded => return Err(Unobserved::Call),
            _ => {}
        }
    }
    match pending_exec
        .into_iter()
        .find(|(pid, (time, _))| !began_after(*pid, *time))
    {
        Some((_, (_, image))) => Err(Unobserved::Program(native_path(image))),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests;
