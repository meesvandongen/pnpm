//! The `ntdll` calls that change paths without opening them for writing
//! (renames, links, deletions), and process creation.

use super::{
    hooks::{Status, log_object, log_path, original},
    path_bytes,
    paths::{ObjectAttributes, dos_path, handle_path},
};
use crate::log::guarded;
use pnpm_fs_access_protocol::{Access, Event};
use std::{
    ffi::{CStr, c_void},
    sync::atomic::AtomicPtr,
};
use windows_sys::Win32::{
    Foundation::HANDLE,
    System::Threading::{GetProcessId, QueryFullProcessImageNameW},
};

type NtSetInformationFile =
    unsafe extern "system" fn(HANDLE, *mut c_void, *const c_void, u32, u32) -> Status;
type NtDeleteFile = unsafe extern "system" fn(*const ObjectAttributes) -> Status;
type NtCreateUserProcess = unsafe extern "system" fn(
    *mut HANDLE,
    *mut HANDLE,
    u32,
    u32,
    *const c_void,
    *const c_void,
    u32,
    u32,
    *mut c_void,
    *mut c_void,
    *mut c_void,
) -> Status;

static NT_SET_INFORMATION_FILE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static NT_DELETE_FILE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static NT_CREATE_USER_PROCESS: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

/// The `ntdll` functions this module hooks, each required.
pub(super) fn hooks() -> [(&'static CStr, &'static AtomicPtr<c_void>, *mut c_void, bool); 3] {
    [
        (
            c"NtSetInformationFile",
            &NT_SET_INFORMATION_FILE,
            nt_set_information_file as *mut c_void,
            true,
        ),
        (c"NtDeleteFile", &NT_DELETE_FILE, nt_delete_file as *mut c_void, true),
        (
            c"NtCreateUserProcess",
            &NT_CREATE_USER_PROCESS,
            nt_create_user_process as *mut c_void,
            true,
        ),
    ]
}

const RENAME_OR_LINK_CLASSES: [u32; 6] = [10, 11, 56, 65, 66, 72];
const DISPOSITION: u32 = 13;
const DISPOSITION_EX: u32 = 64;

unsafe extern "system" fn nt_set_information_file(
    handle: HANDLE,
    io_status: *mut c_void,
    information: *const c_void,
    length: u32,
    class: u32,
) -> Status {
    if changes_paths(class) && !information.is_null() {
        guarded(|| {
            // SAFETY: the information the process passed, `length` bytes long.
            let info =
                unsafe { std::slice::from_raw_parts(information.cast::<u8>(), length as usize) };
            for path in changed_paths(handle, class, info) {
                log_path(Access::Write, &path);
            }
        });
    }
    let real: NtSetInformationFile = original(&NT_SET_INFORMATION_FILE);
    // SAFETY: the call as the process made it.
    unsafe { real(handle, io_status, information, length, class) }
}

/// Whether a `NtSetInformationFile` call of `class` can change a path. The
/// other classes, which set a file's position, size, or times, are most of
/// the calls.
fn changes_paths(class: u32) -> bool {
    RENAME_OR_LINK_CLASSES.contains(&class) || matches!(class, DISPOSITION | DISPOSITION_EX)
}

/// The paths a `NtSetInformationFile` call changes: a rename's source and
/// target, a link's new name, and a file marked for deletion.
fn changed_paths(handle: HANDLE, class: u32, info: &[u8]) -> Vec<Vec<u16>> {
    let source = handle_path(handle);
    if RENAME_OR_LINK_CLASSES.contains(&class) {
        let is_rename = !matches!(class, 11 | 72);
        let target = rename_target(info, source.as_deref());
        return [is_rename.then_some(source).flatten(), target]
            .into_iter()
            .flatten()
            .collect();
    }
    let deletes = match class {
        DISPOSITION => info
            .first()
            .is_some_and(|flag| *flag != 0),
        DISPOSITION_EX => info
            .first()
            .is_some_and(|flags| flags & 1 != 0),
        _ => false,
    };
    if deletes { source.into_iter().collect() } else { Vec::new() }
}

/// The target of `FILE_RENAME_INFORMATION` or `FILE_LINK_INFORMATION`: a
/// flags word, a root directory handle, the name's byte length, and the
/// name, on a 64-bit target.
fn rename_target(info: &[u8], source: Option<&[u16]>) -> Option<Vec<u16>> {
    let root = usize::from_le_bytes(info.get(8..16)?.try_into().ok()?) as HANDLE;
    let len = u32::from_le_bytes(info.get(16..20)?.try_into().ok()?) as usize;
    let name: Vec<u16> = info
        .get(20..20 + len)?
        .chunks_exact(2)
        .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
        .collect();
    let base = if !root.is_null() {
        handle_path(root)
    } else if let Some(absolute) = dos_path(&name) {
        return Some(absolute);
    } else {
        // A bare name renames the file within its directory.
        let source = source?;
        let separator = source
            .iter()
            .rposition(|unit| *unit == u16::from(b'\\'))?;
        Some(source[..separator].to_vec())
    }?;
    let mut target = base;
    target.push(u16::from(b'\\'));
    target.extend_from_slice(&name);
    Some(target)
}

unsafe extern "system" fn nt_delete_file(attributes: *const ObjectAttributes) -> Status {
    log_object(Access::Write, attributes);
    let real: NtDeleteFile = original(&NT_DELETE_FILE);
    // SAFETY: the call as the process made it.
    unsafe { real(attributes) }
}

/// Every user-mode process creation ends here. The created process is
/// logged as spawned, so a process that does not load the hook (created
/// through an API other than the hooked `CreateProcess` functions, or of
/// another architecture) makes the record incomplete. Its program is an
/// input.
unsafe extern "system" fn nt_create_user_process(
    process: *mut HANDLE,
    thread: *mut HANDLE,
    process_access: u32,
    thread_access: u32,
    process_attributes: *const c_void,
    thread_attributes: *const c_void,
    process_flags: u32,
    thread_flags: u32,
    parameters: *mut c_void,
    create_info: *mut c_void,
    attribute_list: *mut c_void,
) -> Status {
    let real: NtCreateUserProcess = original(&NT_CREATE_USER_PROCESS);
    // SAFETY: the call as the process made it.
    let status = unsafe {
        real(
            process,
            thread,
            process_access,
            thread_access,
            process_attributes,
            thread_attributes,
            process_flags,
            thread_flags,
            parameters,
            create_info,
            attribute_list,
        )
    };
    if status >= 0 {
        // SAFETY: a successful call wrote the new process's handle.
        let created = unsafe { *process };
        guarded(|| log_created_process(created));
    }
    status
}

fn log_created_process(process: HANDLE) {
    // SAFETY: a process handle the call just returned.
    let child = unsafe { GetProcessId(process) };
    let mut image = vec![0u16; 1024];
    let mut len = image.len() as u32;
    // SAFETY: the buffer's length is passed along with it.
    let named = unsafe { QueryFullProcessImageNameW(process, 0, image.as_mut_ptr(), &raw mut len) };
    image.truncate(if named != 0 { len as usize } else { 0 });
    if !image.is_empty() {
        log_path(Access::Read, &image);
    }
    crate::log::write(Event::Spawned { child, image: &path_bytes(&image) });
}
