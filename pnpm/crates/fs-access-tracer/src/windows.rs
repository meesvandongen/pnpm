//! The Windows recorder. The command is created suspended; once it exists,
//! Detours adds the hook DLL to its imports and copies the log directory
//! in, and the process runs. The hook logs its process's file accesses and
//! injects itself into the processes that one creates.

use crate::{FileAccesses, Unsupported, artifact::embedded, log::read_logs};
use pnpm_detours_sys::{DetourCopyPayloadToProcess, DetourUpdateProcessWithDll};
use pnpm_fs_access_protocol::{
    Event, LOG_DIR_ENV, Record, WINDOWS_PAYLOAD_GUID, encode, max_record_len, native_bytes,
};
use std::{
    ffi::{CString, OsStr, c_char},
    fs::{File, OpenOptions},
    io::{self, Write},
    os::windows::{ffi::OsStrExt, io::AsRawHandle, process::CommandExt},
    process::{Child, Command},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use windows_sys::{
    Win32::{
        Foundation::HANDLE,
        Globalization::{CP_ACP, WideCharToMultiByte},
        System::{Performance::QueryPerformanceCounter, Threading::CREATE_SUSPENDED},
    },
    core::GUID,
};

pub const IS_SUPPORTED: bool = true;

static PAYLOAD_GUID: GUID = GUID::from_u128(WINDOWS_PAYLOAD_GUID);

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtResumeProcess(process: HANDLE) -> i32;
}

pub struct Recorder {
    shared: Arc<Shared>,
}

pub struct Prepared {
    shared: Arc<Shared>,
}

struct Shared {
    log_dir: tempfile::TempDir,
    /// The hook DLL's path in the ANSI code page, as Detours takes it.
    dll_path: CString,
    /// pnpm's own log, which names the processes it started.
    own_log: Mutex<File>,
    incomplete: AtomicBool,
}

impl Recorder {
    pub fn new() -> Result<Self, Unsupported> {
        let hook = embedded!("pnpm_fs_access_hook.dll", "HOOK", executable = false);
        let dll = hook
            .materialize()
            .map_err(|_| Unsupported("the file access hook could not be written to disk"))?;
        let dll_path = ansi(dll.as_os_str())
            .ok_or(Unsupported(
                "the temporary directory's path is not valid in the ANSI code page",
            ))?;
        let log_dir = tempfile::Builder::new()
            .prefix("pnpm-fs-access-")
            .tempdir()
            .map_err(|_| {
                Unsupported("a directory for the file access logs could not be created")
            })?;
        let own_log = OpenOptions::new()
            .create_new(true)
            .append(true)
            .open(log_dir.path().join("pnpm.log"))
            .map_err(|_| Unsupported("the file access log could not be created"))?;
        Ok(Recorder {
            shared: Arc::new(Shared {
                log_dir,
                dll_path,
                own_log: Mutex::new(own_log),
                incomplete: AtomicBool::new(false),
            }),
        })
    }

    #[expect(clippy::unused_self, reason = "the signature of the other platforms' recorders")]
    pub fn command(&self, program: &OsStr) -> Command {
        Command::new(program)
    }

    pub fn prepare(&self, command: &mut Command) -> io::Result<Prepared> {
        command.env(LOG_DIR_ENV, self.shared.log_dir.path()).creation_flags(CREATE_SUSPENDED);
        Ok(Prepared { shared: Arc::clone(&self.shared) })
    }

    pub fn finish(self) -> Option<FileAccesses> {
        let accesses = read_logs(self.shared.log_dir.path()).ok().flatten()?;
        (!self.shared.incomplete.load(Ordering::SeqCst)).then_some(accesses)
    }
}

impl Prepared {
    pub fn started(self, child: &Child) {
        let process = child.as_raw_handle();
        self.shared.log_spawn(child.id());
        if !self.shared.inject(process) {
            self.shared.incomplete.store(true, Ordering::SeqCst);
        }
        // SAFETY: the handle of the process spawned suspended, which runs
        // now whether or not the hook could be added.
        unsafe {
            NtResumeProcess(process);
        }
    }
}

impl Shared {
    fn inject(&self, process: HANDLE) -> bool {
        let dir: Vec<u16> = self.log_dir
            .path()
            .as_os_str()
            .encode_wide()
            .collect();
        let mut dlls: [*const c_char; 1] = [self.dll_path.as_ptr()];
        // SAFETY: a suspended process this process created; the DLL path
        // and the payload live across the calls.
        unsafe {
            DetourUpdateProcessWithDll(process, dlls.as_mut_ptr(), 1) != 0
                && DetourCopyPayloadToProcess(
                    process,
                    &raw const PAYLOAD_GUID,
                    dir.as_ptr().cast(),
                    u32::try_from(dir.len() * 2).unwrap_or(0),
                ) != 0
        }
    }

    /// Log the process as spawned by pnpm, so the record is incomplete
    /// unless the hook starts in it.
    fn log_spawn(&self, child: u32) {
        let image = native_bytes(std::path::Path::new(""));
        let record = Record {
            pid: std::process::id(),
            time: now(),
            event: Event::Spawned { child, image: &image },
        };
        let mut buffer = vec![0u8; max_record_len(image.len())];
        let written = encode(&record, &mut buffer)
            .is_some_and(|len| {
                self.own_log
                    .lock()
                    .expect("the log lock is not poisoned")
                    .write_all(&buffer[..len])
                    .is_ok()
            });
        if !written {
            self.incomplete.store(true, Ordering::SeqCst);
        }
    }
}

fn now() -> u64 {
    let mut counter = 0i64;
    // SAFETY: writes the counter into a live local.
    unsafe {
        QueryPerformanceCounter(&raw mut counter);
    }
    counter as u64
}

/// `text` in the ANSI code page, when every character has a
/// representation there.
fn ansi(text: &OsStr) -> Option<CString> {
    let wide: Vec<u16> = text.encode_wide().collect();
    let mut buffer = vec![0u8; wide.len() * 4 + 1];
    let mut lossy = 0;
    // SAFETY: both buffers' lengths are passed along with them.
    let len = unsafe {
        WideCharToMultiByte(
            CP_ACP,
            0,
            wide.as_ptr(),
            i32::try_from(wide.len()).ok()?,
            buffer.as_mut_ptr(),
            i32::try_from(buffer.len()).ok()?,
            std::ptr::null(),
            &raw mut lossy,
        )
    };
    if len <= 0 || lossy != 0 {
        return None;
    }
    buffer.truncate(len as usize);
    CString::new(buffer).ok()
}

#[cfg(test)]
mod tests;
