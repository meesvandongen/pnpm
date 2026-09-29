use super::{contains, fixture, node};
use std::fs;

#[test]
fn device_paths_leave_the_record_complete() {
    let (_temp, dir) = fixture();
    fs::write(dir.join("input.txt"), "x").unwrap();
    let accesses = node(
        &dir,
        "const { devNull } = require('node:os'); \
         fs.writeFileSync(devNull, 'x'); fs.readFileSync(devNull); fs.readFileSync('input.txt')",
    );
    assert!(contains(&accesses.reads, &dir.join("input.txt")));
}

#[cfg(target_os = "linux")]
#[test]
fn a_path_as_long_as_the_kernel_accepts_is_recorded_whole() {
    let (_temp, dir) = fixture();
    // `PATH_MAX` counts the terminating NUL.
    let name = "a".repeat(4095);
    let accesses = super::helper::record_scenario(&dir, &format!("open {name}"))
        .expect("every access is recorded");
    assert!(contains(&accesses.reads, &dir.join(&name)));
}

#[cfg(target_os = "linux")]
#[test]
fn a_path_longer_than_the_kernel_accepts_leaves_the_record_incomplete() {
    let (_temp, dir) = fixture();
    let name = "a".repeat(5000);
    assert_eq!(
        super::helper::record_scenario(&dir, &format!("open {name}")),
        Err(pnpm_fs_access_tracer::Unobserved::Call),
    );
}

#[cfg(windows)]
#[test]
fn a_path_named_with_short_components_is_recorded_as_its_file() {
    use std::{
        ffi::OsString,
        os::windows::ffi::{OsStrExt, OsStringExt},
        path::PathBuf,
    };
    use windows_sys::Win32::Storage::FileSystem::GetShortPathNameW;
    let (_temp, dir) = fixture();
    fs::write(dir.join("input.txt"), "x").unwrap();
    let long: Vec<u16> = dir
        .as_os_str()
        .encode_wide()
        .chain([0])
        .collect();
    let mut short = vec![0u16; 1024];
    // SAFETY: `long` is NUL-terminated, and the buffer's length is passed
    // along with it.
    let len = unsafe { GetShortPathNameW(long.as_ptr(), short.as_mut_ptr(), short.len() as u32) };
    assert!(len > 0 && (len as usize) < short.len(), "the directory has a short name");
    let short = PathBuf::from(OsString::from_wide(&short[..len as usize]));
    let script = format!(
        "child_process.spawnSync('cmd', ['/d', '/c', 'type {}'], {{ stdio: 'ignore' }})",
        short
            .join("input.txt")
            .display()
            .to_string()
            .replace('\\', "\\\\"),
    );
    let accesses = node(&dir, &script);
    assert!(contains(&accesses.reads, &dir.join("input.txt")));
}
