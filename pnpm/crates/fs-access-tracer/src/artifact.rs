//! Files embedded in pnpm that the recorded processes load or run: they
//! are written to the temporary directory once per version, under a
//! directory named by their contents' hash.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

pub(crate) struct Artifact {
    pub(crate) name: &'static str,
    pub(crate) bytes: &'static [u8],
    pub(crate) hash: &'static str,
    pub(crate) executable: bool,
}

impl Artifact {
    /// The artifact's path on disk, writing it there first if no process
    /// has yet.
    pub(crate) fn materialize(&self) -> io::Result<PathBuf> {
        let dir = std::env::temp_dir().join("pnpm-fs-access").join(self.hash);
        let path = dir.join(self.name);
        if fs::metadata(&path).is_ok_and(|metadata| metadata.len() == self.bytes.len() as u64) {
            return Ok(path);
        }
        fs::create_dir_all(&dir)?;
        let temporary = tempfile::NamedTempFile::new_in(&dir)?;
        fs::write(temporary.path(), self.bytes)?;
        if self.executable {
            make_executable(temporary.path())?;
        }
        // Another process may have put the same bytes there meanwhile.
        match temporary.persist(&path) {
            Ok(_) => Ok(path),
            Err(_) if path.exists() => Ok(path),
            Err(error) => Err(error.error),
        }
    }
}

#[cfg(unix)]
fn make_executable(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
}

#[cfg(not(unix))]
fn make_executable(_: &Path) -> io::Result<()> {
    Ok(())
}

/// An artifact the build script embedded under `PNPM_FS_ACCESS_<name>`.
macro_rules! embedded {
    ($name:literal, $env:literal, executable = $executable:literal) => {
        $crate::artifact::Artifact {
            name: $name,
            bytes: include_bytes!(env!(concat!("PNPM_FS_ACCESS_", $env, "_PATH"))),
            hash: env!(concat!("PNPM_FS_ACCESS_", $env, "_HASH")),
            executable: $executable,
        }
    };
}
pub(crate) use embedded;
