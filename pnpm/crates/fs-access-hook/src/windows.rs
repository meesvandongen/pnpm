//! The Windows hook: a DLL that Detours adds to the import table of every
//! process of the recorded tree. On load it opens the process's log and
//! hooks the `ntdll` file system calls and process creation.

mod hooks;
mod paths;
mod spawn;
mod writes;

use pnpm_detours_sys::{DetourFindPayloadEx, DetourIsHelperProcess, DetourRestoreAfterWith};
use pnpm_fs_access_protocol::{Event, LOG_DIR_ENV, WINDOWS_PAYLOAD_GUID};
use std::{
    ffi::{OsString, c_void},
    os::windows::ffi::{OsStrExt, OsStringExt},
    path::PathBuf,
    ptr,
    sync::{
        OnceLock,
        atomic::{AtomicPtr, Ordering},
    },
};
use windows_sys::{
    Win32::{
        Foundation::{HANDLE, HINSTANCE, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{
            CREATE_NEW, CreateFileW, FILE_APPEND_DATA, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
            FILE_SHARE_WRITE, WriteFile,
        },
        System::{
            LibraryLoader::GetModuleFileNameA, Performance::QueryPerformanceCounter,
            SystemServices::DLL_PROCESS_ATTACH, Threading::GetCurrentProcessId,
        },
    },
    core::{BOOL, GUID},
};

pub(crate) static PAYLOAD_GUID: GUID = GUID::from_u128(WINDOWS_PAYLOAD_GUID);

static LOG_FILE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

/// What a process this one creates needs to load the hook: the path of
/// this DLL in the ANSI code page, NUL-terminated, and the log directory
/// as UTF-16 code units.
pub(crate) struct Injection {
    pub(crate) dll_path: Vec<u8>,
    pub(crate) log_dir: Vec<u16>,
}

pub(crate) static INJECTION: OnceLock<Injection> = OnceLock::new();

pub(crate) fn pid() -> u32 {
    // SAFETY: no preconditions.
    unsafe { GetCurrentProcessId() }
}

pub(crate) fn now() -> u64 {
    let mut counter = 0i64;
    // SAFETY: writes the counter into a live local.
    unsafe {
        QueryPerformanceCounter(&raw mut counter);
    }
    counter as u64
}

pub(crate) fn append(record: &[u8]) {
    let file = LOG_FILE.load(Ordering::Relaxed);
    if file.is_null() {
        return;
    }
    let mut written = 0u32;
    // SAFETY: the handle is this process's log, opened for appending, and
    // `record` lives across the call.
    unsafe {
        WriteFile(
            file,
            record.as_ptr(),
            u32::try_from(record.len()).unwrap_or(0),
            &raw mut written,
            ptr::null_mut(),
        );
    }
}

/// The record's native bytes for a UTF-16 path.
pub(crate) fn path_bytes(path: &[u16]) -> Vec<u8> {
    path.iter()
        .flat_map(|unit| unit.to_le_bytes())
        .collect()
}

pub(crate) fn path_buf(path: &[u16]) -> PathBuf {
    OsString::from_wide(path).into()
}

#[unsafe(no_mangle)]
extern "system" fn DllMain(module: HINSTANCE, reason: u32, _: *mut c_void) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        // SAFETY: runs once, on the loader's thread, before any hook.
        unsafe { attach(module) };
    }
    1
}

/// Open the log and install the hooks. A process that cannot log stays
/// unhooked: without its `Began` record, pnpm treats the tree as not
/// fully recorded.
unsafe fn attach(module: HINSTANCE) {
    // SAFETY: Detours calls with no preconditions.
    unsafe {
        if DetourIsHelperProcess() != 0 {
            return;
        }
        DetourRestoreAfterWith();
    }
    let Some(log_dir) = log_dir() else { return };
    let Some(dll_path) = module_path_ansi(module) else { return };
    if !open_log(&log_dir) {
        return;
    }
    let _ = INJECTION.set(Injection { dll_path, log_dir });
    let image = std::env::current_exe().unwrap_or_default();
    crate::log::write(Event::Began { image: &path_bytes(&wide(image.as_os_str())) });
    if !hooks::attach_all() {
        crate::log::write(Event::Unrecorded);
    }
}

/// The log directory, from the payload pnpm or a hooked parent copied into
/// this process, or else from the environment.
fn log_dir() -> Option<Vec<u16>> {
    let mut size = 0u32;
    // SAFETY: `DetourFindPayloadEx` writes the payload size into a live
    // local and returns memory that lives as long as the process.
    let payload = unsafe { DetourFindPayloadEx(&raw const PAYLOAD_GUID, &raw mut size) };
    if !payload.is_null() && size >= 2 {
        // SAFETY: the payload is `size` bytes of UTF-16 code units.
        let units = unsafe { std::slice::from_raw_parts(payload.cast::<u16>(), size as usize / 2) };
        return Some(units.to_vec());
    }
    std::env::var_os(LOG_DIR_ENV).map(|dir| wide(&dir))
}

fn wide(text: &std::ffi::OsStr) -> Vec<u16> {
    text.encode_wide().collect()
}

fn module_path_ansi(module: HINSTANCE) -> Option<Vec<u8>> {
    let mut buffer = vec![0u8; 1024];
    // SAFETY: the buffer's length is passed along with it.
    let len = unsafe { GetModuleFileNameA(module, buffer.as_mut_ptr(), buffer.len() as u32) };
    if len == 0 || len as usize >= buffer.len() {
        return None;
    }
    buffer.truncate(len as usize + 1);
    Some(buffer)
}

fn open_log(log_dir: &[u16]) -> bool {
    let name = format!("\\{}-{}.log", pid(), now());
    let mut path: Vec<u16> = log_dir.to_vec();
    path.extend(name.encode_utf16());
    path.push(0);
    // SAFETY: `path` is NUL-terminated and lives across the call.
    let file: HANDLE = unsafe {
        CreateFileW(
            path.as_ptr(),
            FILE_APPEND_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    if file == INVALID_HANDLE_VALUE {
        return false;
    }
    LOG_FILE.store(file, Ordering::Relaxed);
    true
}
