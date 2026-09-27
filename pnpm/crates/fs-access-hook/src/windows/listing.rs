//! Directory queries. A query names the entries it wants with a mask: all
//! of them, one exact name (`FindFirstFileW` looking up a single path, as
//! `cmd` does for `if exist` and `GetLongPathNameW` does per component),
//! or a wildcard pattern (`cmd` looking for `node.*` when it runs `node`).
//! Each is logged as what it can observe: a listing, a probe of the one
//! path, or a match of the pattern.

use super::{
    hooks::{Status, log_path, original},
    path_buf, path_bytes,
    paths::{UnicodeString, handle_path, unicode_units},
};
use crate::log::guarded;
use pnpm_fs_access_protocol::{Access, PathState};
use std::{
    cell::Cell,
    ffi::{CStr, c_void},
    sync::atomic::AtomicPtr,
};
use windows_sys::{
    Win32::Foundation::HANDLE,
    core::{BOOL, PCWSTR},
    w,
};

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
type FindNextFileW = unsafe extern "system" fn(HANDLE, *mut c_void) -> BOOL;

static NT_QUERY_DIRECTORY_FILE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static NT_QUERY_DIRECTORY_FILE_EX: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static FIND_NEXT_FILE_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

thread_local! {
    /// Set while `FindNextFileW` runs. It continues an enumeration whose
    /// first query, made by `FindFirstFileExW`, was logged with its mask;
    /// the queries that continue it pass no mask, and logging them would
    /// turn a lookup of one name into a listing of the whole directory.
    static CONTINUING: Cell<bool> = const { Cell::new(false) };
}

pub(super) fn hooks() -> [(&'static CStr, &'static AtomicPtr<c_void>, *mut c_void, bool); 2] {
    [
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
    ]
}

pub(super) fn kernelbase_hooks()
-> [(PCWSTR, &'static CStr, &'static AtomicPtr<c_void>, *mut c_void); 1] {
    [(w!("kernelbase.dll"), c"FindNextFileW", &FIND_NEXT_FILE_W, find_next_file_w as *mut c_void)]
}

/// What a directory query with a mask can observe.
#[derive(Debug, PartialEq, Eq)]
enum Query {
    Everything,
    Name,
    Pattern,
}

fn query(mask: &[u16]) -> Query {
    const WILDCARDS: &[u8] = b"*?<>\"";
    if mask.is_empty() || mask == [u16::from(b'*')] {
        Query::Everything
    } else if mask
        .iter()
        .any(|unit| {
            WILDCARDS
                .iter()
                .any(|wildcard| *unit == u16::from(*wildcard))
        })
    {
        Query::Pattern
    } else {
        Query::Name
    }
}

/// Log a query of the directory open as `handle` for the entries `mask`
/// names.
///
/// # Safety
///
/// `mask` is null or points at a valid `UNICODE_STRING`.
unsafe fn log_query(handle: HANDLE, mask: *const UnicodeString) {
    if CONTINUING.try_with(Cell::get).unwrap_or(false) {
        return;
    }
    // SAFETY: the caller's guarantee.
    let mask = unsafe { unicode_units(mask) }.unwrap_or(&[]);
    guarded(|| {
        let Some(dir) = handle_path(handle) else { return };
        let mut named = dir.clone();
        named.push(u16::from(b'\\'));
        named.extend_from_slice(mask);
        match query(mask) {
            Query::Everything => log_path(Access::List, &dir),
            Query::Name => log_path(Access::Probe, &named),
            Query::Pattern => {
                crate::log::access(Access::Match, &path_bytes(&named), || {
                    Some(PathState::of(&path_buf(&dir)))
                });
            }
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
    // SAFETY: the mask the process passed to the call.
    unsafe { log_query(handle, name) };
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
    // SAFETY: the mask the process passed to the call.
    unsafe { log_query(handle, name) };
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

unsafe extern "system" fn find_next_file_w(find: HANDLE, data: *mut c_void) -> BOOL {
    let entered = CONTINUING
        .try_with(|continuing| !continuing.replace(true))
        .unwrap_or(false);
    let real: FindNextFileW = original(&FIND_NEXT_FILE_W);
    // SAFETY: the call as the process made it.
    let found = unsafe { real(find, data) };
    if entered {
        let _ = CONTINUING.try_with(|continuing| continuing.set(false));
    }
    found
}
