//! `CreateProcessW` and `CreateProcessA`, hooked so the processes this one
//! creates load the hook too: each is created suspended, has the hook
//! added to its imports and the log directory copied in, and then runs.

use super::{INJECTION, Injection, PAYLOAD_GUID};
use pnpm_detours_sys::{
    CreateProcessA, CreateProcessW, DetourCopyPayloadToProcess, DetourCreateProcessWithDllExA,
    DetourCreateProcessWithDllExW,
};
use std::{
    ffi::{CStr, c_void},
    mem,
    sync::atomic::{AtomicPtr, Ordering},
};
use windows_sys::{
    Win32::{
        Security::SECURITY_ATTRIBUTES,
        System::Threading::{
            CREATE_SUSPENDED, PROCESS_INFORMATION, ResumeThread, STARTUPINFOA, STARTUPINFOW,
        },
    },
    core::{BOOL, PCSTR, PCWSTR, PSTR, PWSTR},
    w,
};

static CREATE_PROCESS_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static CREATE_PROCESS_A: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

/// The functions to hook, in `kernelbase`, where `kernel32` forwards them.
pub(super) fn hooks() -> Vec<(PCWSTR, &'static CStr, &'static AtomicPtr<c_void>, *mut c_void)> {
    vec![
        (
            w!("kernelbase.dll"),
            c"CreateProcessW",
            &CREATE_PROCESS_W,
            create_process_w as *mut c_void,
        ),
        (
            w!("kernelbase.dll"),
            c"CreateProcessA",
            &CREATE_PROCESS_A,
            create_process_a as *mut c_void,
        ),
    ]
}

unsafe extern "system" fn create_process_w(
    application: PCWSTR,
    command_line: PWSTR,
    process_attributes: *const SECURITY_ATTRIBUTES,
    thread_attributes: *const SECURITY_ATTRIBUTES,
    inherit: BOOL,
    flags: u32,
    environment: *const c_void,
    directory: PCWSTR,
    startup: *const STARTUPINFOW,
    information: *mut PROCESS_INFORMATION,
) -> BOOL {
    let pointer = CREATE_PROCESS_W.load(Ordering::Relaxed);
    // SAFETY: the slot holds the trampoline to the original `CreateProcessW`.
    let real: CreateProcessW = unsafe { mem::transmute::<*mut c_void, CreateProcessW>(pointer) };
    let args = (application, command_line, process_attributes, thread_attributes, inherit);
    let rest = (environment, directory, startup, information);
    if let Some(injection) = INJECTION.get() {
        // SAFETY: the process's own arguments, with the process created
        // suspended until the payload is in place.
        let created = unsafe {
            DetourCreateProcessWithDllExW(
                args.0,
                args.1,
                args.2,
                args.3,
                args.4,
                flags | CREATE_SUSPENDED,
                rest.0,
                rest.1,
                rest.2,
                rest.3,
                injection.dll_path.as_ptr().cast(),
                Some(real),
            )
        };
        if created != 0 {
            // SAFETY: the call filled in `information`.
            unsafe { finish(injection, &*information, flags) };
            return created;
        }
    }
    // Created without the hook, the process never logs that it began, so
    // pnpm treats the record as incomplete.
    // SAFETY: the call as the process made it.
    unsafe { real(args.0, args.1, args.2, args.3, args.4, flags, rest.0, rest.1, rest.2, rest.3) }
}

unsafe extern "system" fn create_process_a(
    application: PCSTR,
    command_line: PSTR,
    process_attributes: *const SECURITY_ATTRIBUTES,
    thread_attributes: *const SECURITY_ATTRIBUTES,
    inherit: BOOL,
    flags: u32,
    environment: *const c_void,
    directory: PCSTR,
    startup: *const STARTUPINFOA,
    information: *mut PROCESS_INFORMATION,
) -> BOOL {
    let pointer = CREATE_PROCESS_A.load(Ordering::Relaxed);
    // SAFETY: the slot holds the trampoline to the original `CreateProcessA`.
    let real: CreateProcessA = unsafe { mem::transmute::<*mut c_void, CreateProcessA>(pointer) };
    let args = (application, command_line, process_attributes, thread_attributes, inherit);
    let rest = (environment, directory, startup, information);
    if let Some(injection) = INJECTION.get() {
        // SAFETY: as in `create_process_w`.
        let created = unsafe {
            DetourCreateProcessWithDllExA(
                args.0,
                args.1,
                args.2,
                args.3,
                args.4,
                flags | CREATE_SUSPENDED,
                rest.0,
                rest.1,
                rest.2,
                rest.3,
                injection.dll_path.as_ptr().cast(),
                Some(real),
            )
        };
        if created != 0 {
            // SAFETY: the call filled in `information`.
            unsafe { finish(injection, &*information, flags) };
            return created;
        }
    }
    // SAFETY: the call as the process made it.
    unsafe { real(args.0, args.1, args.2, args.3, args.4, flags, rest.0, rest.1, rest.2, rest.3) }
}

/// Copy the log directory into the new process, and let it run unless its
/// creator asked for it suspended.
///
/// # Safety
///
/// `information` describes a process just created suspended.
unsafe fn finish(injection: &Injection, information: &PROCESS_INFORMATION, flags: u32) {
    // SAFETY: the new process's handle, and a payload that lives across
    // the call.
    unsafe {
        DetourCopyPayloadToProcess(
            information.hProcess,
            &raw const PAYLOAD_GUID,
            injection.log_dir.as_ptr().cast(),
            u32::try_from(injection.log_dir.len() * 2).unwrap_or(0),
        );
        if flags & CREATE_SUSPENDED == 0 {
            ResumeThread(information.hThread);
        }
    }
}
