//! The access log a recorded process tree writes on the platforms where
//! pnpm records file accesses from inside the processes (macOS and
//! Windows): a hook library loaded into every process of the tree appends
//! [`Record`]s to files in the directory [`LOG_DIR_ENV`] names, and pnpm
//! reads them back once the tree is done.
//!
//! Each record is appended with a single write, so a process that dies
//! midway loses at most the record it was writing, which the reader
//! reports as a truncated log.

pub use record::{Access, Event, Record, Truncated, decode_all, encode};
pub use state::PathState;

mod record;
mod state;

/// The environment variable that names the directory a recorded process
/// appends its log to.
pub const LOG_DIR_ENV: &str = "PNPM_FS_ACCESS_LOG";

/// The Detours payload that carries the log directory, as UTF-16 code
/// units, into a Windows process whose environment may not.
pub const WINDOWS_PAYLOAD_GUID: u128 = 0x6f0e_43a1_2b7d_4c58_9d1e_8a3f_5c20_b741;

/// The longest record [`encode`] writes for a path of `path_len` bytes.
#[must_use]
pub const fn max_record_len(path_len: usize) -> usize {
    record::HEADER_LEN + record::MAX_PAYLOAD_LEN + path_len
}

/// The path a record's native bytes spell. See [`Event`].
#[must_use]
pub fn native_path(bytes: &[u8]) -> std::path::PathBuf {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        std::ffi::OsStr::from_bytes(bytes).into()
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
            .collect();
        std::ffi::OsString::from_wide(&units).into()
    }
}

/// The native bytes of `path` for a record. See [`Event`].
#[must_use]
pub fn native_bytes(path: &std::path::Path) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes().to_vec()
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        path.as_os_str()
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect()
    }
}
