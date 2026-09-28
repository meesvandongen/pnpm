use super::{
    COREUTILS_ENV, INSERT_ENV, SHELL_ENV, Setup, has_arm64e_slice, shebang, with_hook_env,
    without_hook,
};
use pnpm_fs_access_protocol::LOG_DIR_ENV;
use std::{ffi::CString, fs, path::Path};

fn setup() -> Setup {
    Setup {
        log_dir: b"/tmp/logs".to_vec(),
        hook: b"/tmp/hook.dylib".to_vec(),
        shell: b"/tmp/oils".to_vec(),
        coreutils: b"/tmp/coreutils".to_vec(),
    }
}

fn env(entries: &[&str]) -> Vec<CString> {
    entries
        .iter()
        .map(|entry| CString::new(*entry).unwrap())
        .collect()
}

fn value<'a>(env: &'a [CString], name: &str) -> Option<&'a str> {
    env.iter()
        .filter_map(|entry| entry.to_str().ok())
        .find_map(|entry| entry.strip_prefix(name)?.strip_prefix('='))
}

fn script(dir: &Path, contents: &[u8]) -> std::path::PathBuf {
    let path = dir.join("script");
    fs::write(&path, contents).unwrap();
    path
}

/// An interpreter and its argument.
type Shebang<'a> = (&'a str, Option<&'a str>);

#[test]
fn a_shebang_names_the_interpreter_and_its_one_argument() {
    let dir = tempfile::tempdir().unwrap();
    let cases: [(&[u8], Option<Shebang<'_>>); 5] = [
        (b"#!/bin/sh\necho", Some(("/bin/sh", None))),
        (b"#!  /bin/bash  \n", Some(("/bin/bash", None))),
        (b"#!/usr/bin/env node --flag\n", Some(("/usr/bin/env", Some("node --flag")))),
        (b"echo no shebang\n", None),
        (b"#!/bin/sh", None),
    ];
    for (contents, expected) in cases {
        let parsed = shebang(&script(dir.path(), contents));
        let parsed = parsed
            .as_ref()
            .map(|(interpreter, argument)| {
                (
                    interpreter.to_str().unwrap(),
                    argument
                        .as_ref()
                        .map(|argument| argument.to_str().unwrap()),
                )
            });
        assert_eq!(parsed, expected, "{}", String::from_utf8_lossy(contents));
    }
}

#[test]
fn the_hook_environment_replaces_stale_values_and_keeps_other_libraries() {
    let setup = setup();
    let env = with_hook_env(
        &setup,
        env(&[
            "PATH=/bin",
            "DYLD_INSERT_LIBRARIES=/other.dylib",
            &format!("{LOG_DIR_ENV}=/stale"),
            &format!("{SHELL_ENV}=/stale"),
        ]),
    );
    assert_eq!(value(&env, "PATH"), Some("/bin"));
    assert_eq!(value(&env, INSERT_ENV), Some("/other.dylib:/tmp/hook.dylib"));
    assert_eq!(value(&env, LOG_DIR_ENV), Some("/tmp/logs"));
    assert_eq!(value(&env, SHELL_ENV), Some("/tmp/oils"));
    assert_eq!(value(&env, COREUTILS_ENV), Some("/tmp/coreutils"));
    let names: Vec<&str> = env
        .iter()
        .filter_map(|entry| entry.to_str().ok()?.split('=').next())
        .collect();
    assert_eq!(
        names
            .iter()
            .filter(|name| **name == LOG_DIR_ENV)
            .count(),
        1,
        "{names:?}"
    );
}

#[test]
fn the_hook_is_inserted_once() {
    let setup = setup();
    for (existing, expected) in [
        (None, "/tmp/hook.dylib"),
        (Some(""), "/tmp/hook.dylib"),
        (Some("/tmp/hook.dylib"), "/tmp/hook.dylib"),
        (Some("/a.dylib:/tmp/hook.dylib"), "/a.dylib:/tmp/hook.dylib"),
    ] {
        let start: Vec<String> = existing
            .map(|value| format!("{INSERT_ENV}={value}"))
            .into_iter()
            .collect();
        let start: Vec<&str> = start
            .iter()
            .map(String::as_str)
            .collect();
        let once = with_hook_env(&setup, env(&start));
        let twice = with_hook_env(&setup, once.clone());
        assert_eq!(value(&once, INSERT_ENV), Some(expected), "{existing:?}");
        assert_eq!(once, twice, "{existing:?}");
    }
}

#[test]
fn a_program_without_the_hook_keeps_the_other_libraries() {
    let setup = setup();
    let kept =
        without_hook(&setup, env(&["PATH=/bin", "DYLD_INSERT_LIBRARIES=/a.dylib:/tmp/hook.dylib"]));
    assert_eq!(value(&kept, INSERT_ENV), Some("/a.dylib"));
    assert_eq!(value(&kept, "PATH"), Some("/bin"));
    let removed = without_hook(&setup, env(&["DYLD_INSERT_LIBRARIES=/tmp/hook.dylib"]));
    assert_eq!(value(&removed, INSERT_ENV), None);
}

/// A thin 64-bit Mach-O header for the CPU type and subtype.
fn thin(cpu_type: u32, cpu_subtype: u32) -> Vec<u8> {
    [0xfeed_facf_u32, cpu_type, cpu_subtype]
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect()
}

/// A universal header with a slice for each CPU type and subtype.
fn fat(magic: u32, entry_len: usize, slices: &[(u32, u32)]) -> Vec<u8> {
    let mut bytes = [magic, u32::try_from(slices.len()).unwrap()]
        .iter()
        .flat_map(|word| word.to_be_bytes())
        .collect::<Vec<u8>>();
    for (cpu_type, cpu_subtype) in slices {
        let mut entry = vec![0u8; entry_len];
        entry[..4].copy_from_slice(&cpu_type.to_be_bytes());
        entry[4..8].copy_from_slice(&cpu_subtype.to_be_bytes());
        bytes.extend(entry);
    }
    bytes
}

#[test]
fn an_arm64e_slice_is_found_in_thin_and_universal_binaries() {
    const ARM64: u32 = 0x0100_000c;
    const X86_64: u32 = 0x0100_0007;
    // Apple's arm64e binaries set the pointer-authentication ABI bits.
    const ARM64E: u32 = 0x8000_0002;
    let dir = tempfile::tempdir().unwrap();
    let cases: [(&str, Vec<u8>, bool); 7] = [
        ("thin arm64", thin(ARM64, 0), false),
        ("thin arm64e", thin(ARM64, ARM64E), true),
        ("thin x86_64", thin(X86_64, 3), false),
        (
            "universal x86_64 and arm64e",
            fat(0xcafe_babe, 20, &[(X86_64, 3), (ARM64, ARM64E)]),
            true,
        ),
        ("universal x86_64 and arm64", fat(0xcafe_babe, 20, &[(X86_64, 3), (ARM64, 0)]), false),
        ("64-bit universal with arm64e", fat(0xcafe_babf, 32, &[(ARM64, 2)]), true),
        ("a script", b"#!/bin/sh\n".to_vec(), false),
    ];
    for (name, contents, expected) in cases {
        let path = dir.path().join("binary");
        fs::write(&path, contents).unwrap();
        assert_eq!(has_arm64e_slice(&path), expected, "{name}");
    }
    assert!(!has_arm64e_slice(&dir.path().join("missing")));
}
