//! What a hooked `exec` or `posix_spawn` runs on macOS: the program,
//! arguments, and environment, and whether the hook can load into the
//! program at all. Other Unix platforms build it only for its tests.
#![cfg_attr(
    not(target_os = "macos"),
    allow(dead_code, reason = "only the tests use it outside macOS")
)]

use pnpm_fs_access_protocol::LOG_DIR_ENV;
use std::{
    ffi::{CStr, CString, OsStr, c_char},
    io::Read,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    ptr,
};

/// The environment variables pnpm sets for the hook, besides
/// [`LOG_DIR_ENV`]: the shell and the core utilities to run in place of
/// the system's.
pub(crate) const SHELL_ENV: &str = "PNPM_FS_ACCESS_SHELL";
pub(crate) const COREUTILS_ENV: &str = "PNPM_FS_ACCESS_COREUTILS";
pub(crate) const INSERT_ENV: &str = "DYLD_INSERT_LIBRARIES";

/// The variables this process was started with, handed on to the
/// processes it starts.
pub(crate) struct Setup {
    pub(crate) log_dir: Vec<u8>,
    pub(crate) hook: Vec<u8>,
    pub(crate) shell: Vec<u8>,
    pub(crate) coreutils: Vec<u8>,
}

/// The interpreter a `#!` line names, and its one argument.
pub(crate) fn shebang(script: &Path) -> Option<(PathBuf, Option<CString>)> {
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
pub(crate) fn with_hook_env(setup: &Setup, env: Vec<CString>) -> Vec<CString> {
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
pub(crate) fn without_hook(setup: &Setup, env: Vec<CString>) -> Vec<CString> {
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
pub(crate) fn loads_hook(program: &Path) -> bool {
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

/// Whether `sed`, run as `args` (`argv[0]` first), touches no file: it
/// filters standard input with plain `s` substitutions. The shims that
/// pnpm and npm write in `node_modules/.bin` run it that way to normalize
/// their own path, and a protected `sed` runs without the hook. A file
/// operand, an option other than `-n`, `-E`, `-r`, `-u`, and `-e`, or a
/// command that reads or writes a file (`r`, `w`, a `w` flag) does not
/// qualify.
pub(crate) fn sed_touches_no_files(args: &[CString]) -> bool {
    let mut scripts: Vec<&[u8]> = Vec::new();
    let mut operands: Vec<&[u8]> = Vec::new();
    let mut rest = args
        .iter()
        .skip(1)
        .map(CString::as_bytes);
    while let Some(arg) = rest.next() {
        match arg {
            b"-n" | b"-E" | b"-r" | b"-u" => {}
            b"-e" => match rest.next() {
                Some(script) => scripts.push(script),
                None => return false,
            },
            _ if arg.starts_with(b"-e") => scripts.push(&arg[2..]),
            _ if arg.starts_with(b"-") => return false,
            _ => operands.push(arg),
        }
    }
    if scripts.is_empty() {
        // Without `-e`, the first operand is the script.
        if operands.len() != 1 {
            return false;
        }
        scripts = std::mem::take(&mut operands);
    }
    operands.is_empty() && scripts.iter().all(|script| is_plain_substitution(script))
}

/// Whether `script` is one `s` command whose flags neither write a file
/// nor run a command.
fn is_plain_substitution(script: &[u8]) -> bool {
    let [b's', delimiter, rest @ ..] = script else { return false };
    if matches!(delimiter, b'\\' | b'\n') {
        return false;
    }
    let mut delimiters = 0;
    let mut escaped = false;
    let mut flags = None;
    for (index, byte) in rest.iter().enumerate() {
        if escaped {
            escaped = false;
        } else if *byte == b'\\' {
            escaped = true;
        } else if *byte == b'\n' {
            return false;
        } else if byte == delimiter {
            delimiters += 1;
            if delimiters == 2 {
                flags = Some(&rest[index + 1..]);
                break;
            }
        }
    }
    flags.is_some_and(|flags| {
        flags
            .iter()
            .all(|flag| matches!(flag, b'g' | b'p' | b'I' | b'i' | b'0'..=b'9'))
    })
}

/// # Safety
///
/// `array` is null or a null-terminated array of NUL-terminated strings.
pub(crate) unsafe fn strings(array: *const *const c_char) -> Vec<CString> {
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

pub(crate) fn pointers(strings: &[CString]) -> Vec<*const c_char> {
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

#[cfg(test)]
mod tests;
