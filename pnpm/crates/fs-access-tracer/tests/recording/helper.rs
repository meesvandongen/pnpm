//! Scenarios this test binary runs inside a recorded process: it starts
//! itself again under the recorder, running only [`scenario`], which does
//! what the scenario the environment names asks for. This reaches calls no
//! ready-made program makes, such as system calls that bypass libc.

use super::run;
use pnpm_fs_access_tracer::{FileAccesses, Recorder, Unobserved};
use std::{ffi::OsStr, path::Path};

const SCENARIO_ENV: &str = "PNPM_FS_ACCESS_TEST_SCENARIO";

/// Run the scenario `name` in `dir` under a recorder.
pub(crate) fn record_scenario(dir: &Path, name: &str) -> Result<FileAccesses, Unobserved> {
    let recorder = Recorder::new().expect("this system supports recording");
    let program = std::env::current_exe().unwrap();
    let mut command = recorder.command(program.as_os_str());
    command
        .args(["helper::scenario", "--exact", "--nocapture", "--test-threads", "1"])
        .env(SCENARIO_ENV, name)
        .current_dir(dir);
    let (status, accesses) = run(recorder, command);
    assert!(status.success(), "the {name} scenario exits cleanly");
    accesses
}

/// Does nothing unless this binary runs as a recorded scenario.
#[test]
fn scenario() {
    let Some(name) = std::env::var_os(SCENARIO_ENV) else { return };
    run_scenario(&name);
}

fn run_scenario(name: &OsStr) {
    match name.to_str() {
        Some("rust std") => rust_std(),
        #[cfg(target_os = "linux")]
        Some("raw system calls") => linux::raw_system_calls(),
        #[cfg(target_os = "linux")]
        Some(name) if name.starts_with("open ") => linux::open(&name["open ".len()..]),
        #[cfg(windows)]
        Some("create process") => windows::create_process(),
        other => panic!("no scenario {other:?}"),
    }
}

/// What a program built with Rust does through `std::fs`.
fn rust_std() {
    let _ = std::fs::metadata("stat.txt");
    let _ = std::fs::read("read.txt");
    let _ = std::fs::read_dir("dir").map(|mut entries| entries.next());
    std::fs::write("written.txt", "x").unwrap();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::CString;

    fn c_path(path: &str) -> CString {
        CString::new(path).unwrap()
    }

    /// File system calls made straight to the kernel, the way Go programs
    /// such as esbuild make them, not through libc's wrappers.
    pub(super) fn raw_system_calls() {
        let read = c_path("raw-read.txt");
        let opened = c_path("raw-openat2.txt");
        let stated = c_path("raw-stat.txt");
        let listed = c_path("raw-dir");
        let how = OpenHow { flags: libc::O_RDONLY as u64, mode: 0, resolve: 0 };
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        let mut entries = [0u8; 4096];
        // SAFETY: each call gets NUL-terminated paths and buffers that live
        // across it; the descriptors it returns are closed.
        unsafe {
            close(libc::syscall(libc::SYS_openat, libc::AT_FDCWD, read.as_ptr(), libc::O_RDONLY));
            close(libc::syscall(
                libc::SYS_openat2,
                libc::AT_FDCWD,
                opened.as_ptr(),
                &raw const how,
                size_of::<OpenHow>(),
            ));
            libc::syscall(
                libc::SYS_newfstatat,
                libc::AT_FDCWD,
                stated.as_ptr(),
                stat.as_mut_ptr(),
                0,
            );
            let dir = libc::syscall(
                libc::SYS_openat,
                libc::AT_FDCWD,
                listed.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY,
            );
            libc::syscall(libc::SYS_getdents64, dir, entries.as_mut_ptr(), entries.len());
            close(dir);
        }
    }

    /// Open `path` for reading through libc.
    pub(super) fn open(path: &str) {
        let path = c_path(path);
        // SAFETY: `path` is NUL-terminated and lives across the call.
        unsafe { close(i64::from(libc::open(path.as_ptr(), libc::O_RDONLY))) };
    }

    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    unsafe fn close(fd: i64) {
        if fd >= 0 {
            // SAFETY: the caller's descriptor, which nothing uses again.
            unsafe { libc::close(fd as i32) };
        }
    }
}

#[cfg(windows)]
mod windows {
    use std::ptr;
    use windows_sys::Win32::System::Threading::{
        CreateProcessA, CreateProcessW, PROCESS_INFORMATION, STARTUPINFOA, STARTUPINFOW,
    };

    /// Programs that do not exist, started through `CreateProcessA` and
    /// `CreateProcessW` directly.
    pub(super) fn create_process() {
        let mut ansi = *b"C:\\pnpm_fs_access_no_such_program_a.exe\0";
        let mut wide: Vec<u16> =
            "C:\\pnpm_fs_access_no_such_program_w.exe\0".encode_utf16().collect();
        // SAFETY: zeroed start-up and process information structures are
        // valid, with their sizes set, and the command lines are
        // NUL-terminated and writable, as `CreateProcess` requires.
        unsafe {
            let mut startup_a: STARTUPINFOA = std::mem::zeroed();
            startup_a.cb = size_of::<STARTUPINFOA>() as u32;
            let mut startup_w: STARTUPINFOW = std::mem::zeroed();
            startup_w.cb = size_of::<STARTUPINFOW>() as u32;
            let mut information: PROCESS_INFORMATION = std::mem::zeroed();
            let created_a = CreateProcessA(
                ptr::null(),
                ansi.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                0,
                0,
                ptr::null(),
                ptr::null(),
                &raw const startup_a,
                &raw mut information,
            );
            let created_w = CreateProcessW(
                ptr::null(),
                wide.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                0,
                0,
                ptr::null(),
                ptr::null(),
                &raw const startup_w,
                &raw mut information,
            );
            assert_eq!((created_a, created_w), (0, 0), "the programs do not exist");
        }
    }
}
