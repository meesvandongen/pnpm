//! The `ntdll` calls every Windows file access goes through, hooked with
//! Detours. Each hook logs the access, then makes the call as it was made.

use super::{
    guarded, path_buf, path_bytes,
    paths::{ObjectAttributes, UnicodeString, handle_path, object_path},
    spawn, writes,
};
use pnpm_detours_sys::{
    DetourAttach, DetourTransactionBegin, DetourTransactionCommit, DetourUpdateThread,
};
use pnpm_fs_access_protocol::{Access, PathState};
use std::{
    ffi::{CStr, c_void},
    mem,
    sync::atomic::{AtomicPtr, Ordering},
};
use windows_sys::{
    Win32::{
        Foundation::HANDLE,
        System::{
            LibraryLoader::{GetModuleHandleW, GetProcAddress},
            Threading::GetCurrentThread,
        },
    },
    core::PCWSTR,
    w,
};

pub(super) type Status = i32;

type NtCreateFile = unsafe extern "system" fn(
    *mut HANDLE,
    u32,
    *const ObjectAttributes,
    *mut c_void,
    *const i64,
    u32,
    u32,
    u32,
    u32,
    *const c_void,
    u32,
) -> Status;
type NtOpenFile = unsafe extern "system" fn(
    *mut HANDLE,
    u32,
    *const ObjectAttributes,
    *mut c_void,
    u32,
    u32,
) -> Status;
type NtQueryAttributesFile =
    unsafe extern "system" fn(*const ObjectAttributes, *mut c_void) -> Status;
type NtQueryDirectoryFile = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    *mut c_void,
    *mut c_void,
    *mut c_void,
    *mut c_void,
    u32,
    u32,
    u8,
    *const UnicodeString,
    u8,
) -> Status;
type NtQueryDirectoryFileEx = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    *mut c_void,
    *mut c_void,
    *mut c_void,
    *mut c_void,
    u32,
    u32,
    u32,
    *const UnicodeString,
) -> Status;
static NT_CREATE_FILE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static NT_OPEN_FILE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static NT_QUERY_ATTRIBUTES_FILE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static NT_QUERY_FULL_ATTRIBUTES_FILE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static NT_QUERY_DIRECTORY_FILE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static NT_QUERY_DIRECTORY_FILE_EX: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

/// A function to hook: where it lives, the slot that keeps the original,
/// and whether the record is incomplete without it.
struct Hook {
    module: PCWSTR,
    name: &'static CStr,
    original: &'static AtomicPtr<c_void>,
    detour: *mut c_void,
    required: bool,
}

fn hooks() -> Vec<Hook> {
    let files = [
        (c"NtCreateFile", &NT_CREATE_FILE, nt_create_file as *mut c_void, true),
        (c"NtOpenFile", &NT_OPEN_FILE, nt_open_file as *mut c_void, true),
        (
            c"NtQueryAttributesFile",
            &NT_QUERY_ATTRIBUTES_FILE,
            nt_query_attributes_file as *mut c_void,
            true,
        ),
        (
            c"NtQueryFullAttributesFile",
            &NT_QUERY_FULL_ATTRIBUTES_FILE,
            nt_query_full_attributes_file as *mut c_void,
            true,
        ),
        (
            c"NtQueryDirectoryFile",
            &NT_QUERY_DIRECTORY_FILE,
            nt_query_directory_file as *mut c_void,
            true,
        ),
        (
            c"NtQueryDirectoryFileEx",
            &NT_QUERY_DIRECTORY_FILE_EX,
            nt_query_directory_file_ex as *mut c_void,
            false,
        ),
    ];
    let ntdll = files
        .into_iter()
        .chain(writes::hooks())
        .map(|(name, original, detour, required)| Hook {
            module: w!("ntdll.dll"),
            name,
            original,
            detour,
            required,
        });
    let kernelbase = spawn::hooks()
        .into_iter()
        .map(|(module, name, original, detour)| Hook {
            module,
            name,
            original,
            detour,
            required: true,
        });
    ntdll.chain(kernelbase).collect()
}

/// Hook every function, or none: `false` when a required one is missing
/// or Detours refuses.
pub(super) fn attach_all() -> bool {
    let hooks = hooks();
    let mut found = Vec::new();
    for hook in &hooks {
        // SAFETY: the module and function names are NUL-terminated.
        let address = unsafe {
            let module = GetModuleHandleW(hook.module);
            if module.is_null() { None } else { GetProcAddress(module, hook.name.as_ptr().cast()) }
        };
        match address {
            Some(address) => found.push((hook, address as *mut c_void)),
            None if hook.required => return false,
            None => {}
        }
    }
    // SAFETY: a Detours transaction on the loading thread, before any
    // other code of this DLL runs; each slot is updated to the trampoline
    // that calls the original.
    unsafe {
        if DetourTransactionBegin() != 0 {
            return false;
        }
        DetourUpdateThread(GetCurrentThread());
        for (hook, address) in found {
            hook.original.store(address, Ordering::SeqCst);
            DetourAttach(hook.original.as_ptr(), hook.detour);
        }
        DetourTransactionCommit() == 0
    }
}

pub(super) fn log_path(access: Access, path: &[u16]) {
    let bytes = path_bytes(path);
    crate::log::access(access, &bytes, || {
        (!matches!(access, Access::Write)).then(|| PathState::of(&path_buf(path)))
    });
}

const FILE_READ_DATA: u32 = 0x0001;
const FILE_WRITE_DATA: u32 = 0x0002;
const FILE_APPEND_DATA: u32 = 0x0004;
const FILE_EXECUTE: u32 = 0x0020;
const DELETE: u32 = 0x0001_0000;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_EXECUTE: u32 = 0x2000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_READ: u32 = 0x8000_0000;
const FILE_OPEN: u32 = 1;
const FILE_OPEN_IF: u32 = 3;
const FILE_DIRECTORY_FILE: u32 = 0x0001;
const FILE_DELETE_ON_CLOSE: u32 = 0x1000;

/// How an open with these rights, disposition, and options uses its path.
fn open_access(desired: u32, disposition: u32, options: u32) -> Access {
    let writes = desired
        & (FILE_WRITE_DATA
            | FILE_APPEND_DATA
            | DELETE
            | GENERIC_WRITE
            | GENERIC_ALL
            | MAXIMUM_ALLOWED)
        != 0
        || disposition != FILE_OPEN
        || options & FILE_DELETE_ON_CLOSE != 0;
    let reads = desired
        & (FILE_READ_DATA
            | FILE_EXECUTE
            | GENERIC_READ
            | GENERIC_EXECUTE
            | GENERIC_ALL
            | MAXIMUM_ALLOWED)
        != 0;
    let keeps_contents = matches!(disposition, FILE_OPEN | FILE_OPEN_IF);
    match (writes, reads) {
        (true, true) if keeps_contents && options & FILE_DIRECTORY_FILE == 0 => Access::ReadWrite,
        (true, _) => Access::Write,
        (false, true) if options & FILE_DIRECTORY_FILE == 0 => Access::Read,
        (false, _) => Access::Probe,
    }
}

pub(super) fn log_object(access: Access, attributes: *const ObjectAttributes) {
    guarded(|| {
        // SAFETY: the attributes the process passed to the call.
        if let Some(path) = unsafe { object_path(attributes) } {
            log_path(access, &path);
        }
    });
}

pub(super) fn original<T: Copy>(slot: &AtomicPtr<c_void>) -> T {
    let pointer = slot.load(Ordering::Relaxed);
    // SAFETY: each slot holds the trampoline of the function whose type
    // the hook reading it names.
    unsafe { mem::transmute_copy::<*mut c_void, T>(&pointer) }
}

unsafe extern "system" fn nt_create_file(
    handle: *mut HANDLE,
    desired: u32,
    attributes: *const ObjectAttributes,
    io_status: *mut c_void,
    allocation_size: *const i64,
    file_attributes: u32,
    share: u32,
    disposition: u32,
    options: u32,
    ea: *const c_void,
    ea_len: u32,
) -> Status {
    log_object(open_access(desired, disposition, options), attributes);
    let real: NtCreateFile = original(&NT_CREATE_FILE);
    // SAFETY: the call as the process made it.
    unsafe {
        real(
            handle,
            desired,
            attributes,
            io_status,
            allocation_size,
            file_attributes,
            share,
            disposition,
            options,
            ea,
            ea_len,
        )
    }
}

unsafe extern "system" fn nt_open_file(
    handle: *mut HANDLE,
    desired: u32,
    attributes: *const ObjectAttributes,
    io_status: *mut c_void,
    share: u32,
    options: u32,
) -> Status {
    log_object(open_access(desired, FILE_OPEN, options), attributes);
    let real: NtOpenFile = original(&NT_OPEN_FILE);
    // SAFETY: the call as the process made it.
    unsafe { real(handle, desired, attributes, io_status, share, options) }
}

unsafe extern "system" fn nt_query_attributes_file(
    attributes: *const ObjectAttributes,
    information: *mut c_void,
) -> Status {
    log_object(Access::Probe, attributes);
    let real: NtQueryAttributesFile = original(&NT_QUERY_ATTRIBUTES_FILE);
    // SAFETY: the call as the process made it.
    unsafe { real(attributes, information) }
}

unsafe extern "system" fn nt_query_full_attributes_file(
    attributes: *const ObjectAttributes,
    information: *mut c_void,
) -> Status {
    log_object(Access::Probe, attributes);
    let real: NtQueryAttributesFile = original(&NT_QUERY_FULL_ATTRIBUTES_FILE);
    // SAFETY: the call as the process made it.
    unsafe { real(attributes, information) }
}

fn log_listing(handle: HANDLE) {
    guarded(|| {
        if let Some(path) = handle_path(handle) {
            log_path(Access::List, &path);
        }
    });
}

unsafe extern "system" fn nt_query_directory_file(
    handle: HANDLE,
    event: HANDLE,
    apc_routine: *mut c_void,
    apc_context: *mut c_void,
    io_status: *mut c_void,
    information: *mut c_void,
    length: u32,
    class: u32,
    single: u8,
    name: *const UnicodeString,
    restart: u8,
) -> Status {
    log_listing(handle);
    let real: NtQueryDirectoryFile = original(&NT_QUERY_DIRECTORY_FILE);
    // SAFETY: the call as the process made it.
    unsafe {
        real(
            handle,
            event,
            apc_routine,
            apc_context,
            io_status,
            information,
            length,
            class,
            single,
            name,
            restart,
        )
    }
}

unsafe extern "system" fn nt_query_directory_file_ex(
    handle: HANDLE,
    event: HANDLE,
    apc_routine: *mut c_void,
    apc_context: *mut c_void,
    io_status: *mut c_void,
    information: *mut c_void,
    length: u32,
    class: u32,
    flags: u32,
    name: *const UnicodeString,
) -> Status {
    log_listing(handle);
    let real: NtQueryDirectoryFileEx = original(&NT_QUERY_DIRECTORY_FILE_EX);
    // SAFETY: the call as the process made it.
    unsafe {
        real(
            handle,
            event,
            apc_routine,
            apc_context,
            io_status,
            information,
            length,
            class,
            flags,
            name,
        )
    }
}
