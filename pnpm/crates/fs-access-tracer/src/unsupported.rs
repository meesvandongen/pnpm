use crate::{FileAccesses, Unsupported};
use std::{
    ffi::OsStr,
    io,
    process::{Child, Command},
};

pub const IS_SUPPORTED: bool = false;

/// Never constructed: [`Recorder::new`] always fails here.
pub struct Recorder;

pub struct Prepared;

impl Prepared {
    #[expect(clippy::unused_self, reason = "the signature of the Linux recorder")]
    pub fn started(self, _: &Child) {}
}

impl Recorder {
    pub fn new() -> Result<Self, Unsupported> {
        Err(Unsupported("recording file accesses is not supported on this platform"))
    }

    #[expect(clippy::unused_self, reason = "the signature of the Linux recorder")]
    pub fn command(&self, program: &OsStr) -> Command {
        Command::new(program)
    }

    #[expect(clippy::unused_self, reason = "the signature of the Linux recorder")]
    pub fn prepare(&self, _: &mut Command) -> io::Result<Prepared> {
        Ok(Prepared)
    }

    #[expect(clippy::unused_self, reason = "the signature of the Linux recorder")]
    pub fn finish(self) -> Option<FileAccesses> {
        None
    }
}
