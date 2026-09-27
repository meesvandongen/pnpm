//! Building the program, arguments, and environment a hooked `exec` or
//! `posix_spawn` runs with.

use super::{COREUTILS_ENV, INSERT_ENV, SHELL_ENV, Setup};
use libc::c_char;
use pnpm_fs_access_protocol::LOG_DIR_ENV;
use std::{
    ffi::{CStr, CString, OsStr},
    io::Read,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    ptr,
};

/// The interpreter a `#!` line names, and its one argument.
pub(super) fn shebang(script: &Path) -> Option<(PathBuf, Option<CString>)> {
    let mut head = [0u8; 256];
    let read = std::fs::File::open(script)
        .ok()?
        .read(&mut head)
        .ok()?;
    let line = head[..read].strip_prefix(b"#!")?;
    let line = &line[..line
        .iter()
        .position(|byte| *byte == b'\n')?];
    let line = line.trim_ascii();
    let split = line
        .iter()
        .position(u8::is_ascii_whitespace)
        .unwrap_or(line.len());
    let interpreter = PathBuf::from(OsStr::from_bytes(&line[..split]));
    let argument = line[split..].trim_ascii();
    let argument = (!argument.is_empty())
        .then(|| CString::new(argument).ok())
        .flatten();
    Some((interpreter, argument))
}

/// `env` with the variables that load and configure the hook.
pub(super) fn with_hook_env(setup: &Setup, env: Vec<CString>) -> Vec<CString> {
    let mut insert: Option<Vec<u8>> = None;
    let mut kept: Vec<CString> = Vec::with_capacity(env.len() + 4);
    for entry in env {
        let bytes = entry.as_bytes();
        let name = bytes
            .split(|byte| *byte == b'=')
            .next()
            .unwrap_or_default();
        if name == INSERT_ENV.as_bytes() {
            insert = Some(bytes[name.len() + 1..].to_vec());
        } else if ![LOG_DIR_ENV, SHELL_ENV, COREUTILS_ENV]
            .iter()
            .any(|own| name == own.as_bytes())
        {
            kept.push(entry);
        }
    }
    let insert = with_hook(setup, insert);
    for (name, value) in [
        (INSERT_ENV, &insert),
        (LOG_DIR_ENV, &setup.log_dir),
        (SHELL_ENV, &setup.shell),
        (COREUTILS_ENV, &setup.coreutils),
    ] {
        let mut entry = name.as_bytes().to_vec();
        entry.push(b'=');
        entry.extend_from_slice(value);
        kept.extend(CString::new(entry));
    }
    kept
}

/// # Safety
///
/// `array` is null or a null-terminated array of NUL-terminated strings.
pub(super) unsafe fn strings(array: *const *const c_char) -> Vec<CString> {
    let mut strings = Vec::new();
    if array.is_null() {
        return strings;
    }
    let mut index = 0;
    // SAFETY: the caller's guarantee.
    unsafe {
        while !(*array.add(index)).is_null() {
            strings.push(CStr::from_ptr(*array.add(index)).to_owned());
            index += 1;
        }
    }
    strings
}

pub(super) fn pointers(strings: &[CString]) -> Vec<*const c_char> {
    strings
        .iter()
        .map(|string| string.as_ptr())
        .chain([ptr::null()])
        .collect()
}

/// A `DYLD_INSERT_LIBRARIES` value that loads the hook, keeping the
/// libraries `existing` loads.
fn with_hook(setup: &Setup, existing: Option<Vec<u8>>) -> Vec<u8> {
    match existing {
        Some(value)
            if value
                .split(|byte| *byte == b':')
                .any(|entry| entry == setup.hook.as_slice()) =>
        {
            value
        }
        Some(mut value) if !value.is_empty() => {
            value.push(b':');
            value.extend_from_slice(&setup.hook);
            value
        }
        _ => setup.hook.clone(),
    }
}
