use std::ffi::{c_char, c_void};
use windows_sys::{
    Win32::{
        Foundation::HANDLE,
        Security::SECURITY_ATTRIBUTES,
        System::Threading::{PROCESS_INFORMATION, STARTUPINFOA, STARTUPINFOW},
    },
    core::{BOOL, GUID, PCSTR, PCWSTR, PSTR, PWSTR},
};

/// The `CreateProcessA` signature that
/// [`DetourCreateProcessWithDllExA`] calls to create the process.
pub type CreateProcessA = unsafe extern "system" fn(
    application_name: PCSTR,
    command_line: PSTR,
    process_attributes: *const SECURITY_ATTRIBUTES,
    thread_attributes: *const SECURITY_ATTRIBUTES,
    inherit_handles: BOOL,
    creation_flags: u32,
    environment: *const c_void,
    current_directory: PCSTR,
    startup_info: *const STARTUPINFOA,
    process_information: *mut PROCESS_INFORMATION,
) -> BOOL;

/// The `CreateProcessW` signature that
/// [`DetourCreateProcessWithDllExW`] calls to create the process.
pub type CreateProcessW = unsafe extern "system" fn(
    application_name: PCWSTR,
    command_line: PWSTR,
    process_attributes: *const SECURITY_ATTRIBUTES,
    thread_attributes: *const SECURITY_ATTRIBUTES,
    inherit_handles: BOOL,
    creation_flags: u32,
    environment: *const c_void,
    current_directory: PCWSTR,
    startup_info: *const STARTUPINFOW,
    process_information: *mut PROCESS_INFORMATION,
) -> BOOL;

// Detours is linked statically, from the library `build.rs` compiles.
unsafe extern "system" {
    pub fn DetourTransactionBegin() -> i32;
    pub fn DetourTransactionCommit() -> i32;
    pub fn DetourUpdateThread(thread: HANDLE) -> i32;
    pub fn DetourAttach(pointer: *mut *mut c_void, detour: *mut c_void) -> i32;
    pub fn DetourRestoreAfterWith() -> BOOL;
    pub fn DetourIsHelperProcess() -> BOOL;
    pub fn DetourFindPayloadEx(guid: *const GUID, size: *mut u32) -> *mut c_void;
    pub fn DetourCopyPayloadToProcess(
        process: HANDLE,
        guid: *const GUID,
        data: *const c_void,
        size: u32,
    ) -> BOOL;
    pub fn DetourUpdateProcessWithDll(
        process: HANDLE,
        dlls: *mut *const c_char,
        count: u32,
    ) -> BOOL;
    pub fn DetourCreateProcessWithDllExW(
        application_name: PCWSTR,
        command_line: PWSTR,
        process_attributes: *const SECURITY_ATTRIBUTES,
        thread_attributes: *const SECURITY_ATTRIBUTES,
        inherit_handles: BOOL,
        creation_flags: u32,
        environment: *const c_void,
        current_directory: PCWSTR,
        startup_info: *const STARTUPINFOW,
        process_information: *mut PROCESS_INFORMATION,
        dll_name: *const c_char,
        create_process: Option<CreateProcessW>,
    ) -> BOOL;
    pub fn DetourCreateProcessWithDllExA(
        application_name: PCSTR,
        command_line: PSTR,
        process_attributes: *const SECURITY_ATTRIBUTES,
        thread_attributes: *const SECURITY_ATTRIBUTES,
        inherit_handles: BOOL,
        creation_flags: u32,
        environment: *const c_void,
        current_directory: PCSTR,
        startup_info: *const STARTUPINFOA,
        process_information: *mut PROCESS_INFORMATION,
        dll_name: *const c_char,
        create_process: Option<CreateProcessA>,
    ) -> BOOL;
}
