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

/// `env` without the hook in `DYLD_INSERT_LIBRARIES`, for a program the
/// hook cannot load into.
pub(super) fn without_hook(setup: &Setup, env: Vec<CString>) -> Vec<CString> {
    env.into_iter()
        .filter_map(|entry| {
            let Some(value) = entry
                .as_bytes()
                .strip_prefix(INSERT_ENV.as_bytes())
                .and_then(|rest| rest.strip_prefix(b"="))
            else {
                return Some(entry);
            };
            let others: Vec<&[u8]> = value
                .split(|byte| *byte == b':')
                .filter(|library| *library != setup.hook.as_slice())
                .collect();
            let mut kept = INSERT_ENV.as_bytes().to_vec();
            kept.push(b'=');
            kept.extend(others.join(&b':'));
            (!others.is_empty())
                .then(|| CString::new(kept).ok())
                .flatten()
        })
        .collect()
}

/// Whether dyld can load the hook into `program`. It refuses an arm64
/// library in an arm64e process, the ABI Apple builds its own programs for,
/// and a program with an arm64e slice runs as one. A script runs as its
/// interpreter.
pub(super) fn loads_hook(program: &Path) -> bool {
    let interpreter = shebang(program).map(|(interpreter, _)| interpreter);
    cfg!(not(target_arch = "aarch64"))
        || !has_arm64e_slice(interpreter.as_deref().unwrap_or(program))
}

fn has_arm64e_slice(binary: &Path) -> bool {
    const FAT_MAGIC: u32 = 0xcafe_babe;
    const FAT_MAGIC_64: u32 = 0xcafe_babf;
    const MH_MAGIC_64_BYTES: u32 = 0xcffa_edfe;
    let mut head = [0u8; 4096];
    let Ok(read) = std::fs::File::open(binary).and_then(|mut file| file.read(&mut head)) else {
        return false;
    };
    let head = &head[..read];
    let word = |offset: usize, read: fn([u8; 4]) -> u32| {
        head.get(offset..offset + 4)
            .and_then(|bytes| bytes.try_into().ok())
            .map(read)
    };
    let fat_slices = |entry_len: usize| {
        let count = word(4, u32::from_be_bytes).unwrap_or(0).min(64) as usize;
        (0..count).any(|index| {
            let at = 8 + index * entry_len;
            is_arm64e(word(at, u32::from_be_bytes), word(at + 4, u32::from_be_bytes))
        })
    };
    match word(0, u32::from_be_bytes) {
        Some(FAT_MAGIC) => fat_slices(20),
        Some(FAT_MAGIC_64) => fat_slices(32),
        Some(MH_MAGIC_64_BYTES) => {
            is_arm64e(word(4, u32::from_le_bytes), word(8, u32::from_le_bytes))
        }
        _ => false,
    }
}

fn is_arm64e(cpu_type: Option<u32>, cpu_subtype: Option<u32>) -> bool {
    const CPU_TYPE_ARM64: u32 = 0x0100_000c;
    const CPU_SUBTYPE_ARM64E: u32 = 2;
    const CPU_SUBTYPE_MASK: u32 = 0xff00_0000;
    cpu_type == Some(CPU_TYPE_ARM64)
        && cpu_subtype.is_some_and(|subtype| subtype & !CPU_SUBTYPE_MASK == CPU_SUBTYPE_ARM64E)
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
