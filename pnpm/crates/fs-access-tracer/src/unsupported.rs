use crate::{FileAccesses, Trace};
use std::{io, process::Command};

pub const IS_SUPPORTED: bool = false;

pub fn trace_command(mut command: Command) -> io::Result<Trace> {
    let status = command.status()?;
    Ok(Trace { status, accesses: FileAccesses::default(), complete: false })
}
