//! Paths as the `ntdll` file calls name them, turned into the DOS paths
//! pnpm compares with its workspace.

pub(super) use crate::dos_path::dos_path;
use std::ffi::c_void;
use windows_sys::Win32::{
    Foundation::HANDLE,
    Storage::FileSystem::{FILE_NAME_NORMALIZED, GetFinalPathNameByHandleW, VOLUME_NAME_DOS},
};

#[repr(C)]
pub(super) struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

#[repr(C)]
pub(super) struct ObjectAttributes {
    length: u32,
    root_directory: HANDLE,
    object_name: *const UnicodeString,
    attributes: u32,
    security_descriptor: *const c_void,
    security_quality_of_service: *const c_void,
}

/// The path an `OBJECT_ATTRIBUTES` names, or `None` when it names no file
/// system path this recorder can resolve.
///
/// # Safety
///
/// `attributes` is null or points at a valid `OBJECT_ATTRIBUTES`.
pub(super) unsafe fn object_path(attributes: *const ObjectAttributes) -> Option<Vec<u16>> {
    // SAFETY: the caller passes the attributes it got from the process.
    let attributes = unsafe { attributes.as_ref()? };
    // SAFETY: as above, for the name the attributes point at.
    let name = unsafe { unicode_units(attributes.object_name)? };
    if attributes.root_directory.is_null() {
        return dos_path(name);
    }
    let mut path = handle_path(attributes.root_directory)?;
    if !name.is_empty() {
        path.push(u16::from(b'\\'));
        path.extend_from_slice(name);
    }
    Some(path)
}

/// The code units of a `UNICODE_STRING`.
///
/// # Safety
///
/// `string` is null or points at a valid `UNICODE_STRING`.
pub(super) unsafe fn unicode_units<'a>(string: *const UnicodeString) -> Option<&'a [u16]> {
    // SAFETY: the caller's guarantee.
    let string = unsafe { string.as_ref()? };
    if string.buffer.is_null() {
        return Some(&[]);
    }
    // SAFETY: a `UNICODE_STRING` holds `length` bytes at `buffer`.
    Some(unsafe { std::slice::from_raw_parts(string.buffer, usize::from(string.length) / 2) })
}

/// The DOS path of an open handle, or `None` when it is not a file.
pub(super) fn handle_path(handle: HANDLE) -> Option<Vec<u16>> {
    let mut buffer = vec![0u16; 512];
    loop {
        // SAFETY: the buffer's length is passed along with it.
        let len = unsafe {
            GetFinalPathNameByHandleW(
                handle,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        } as usize;
        match len {
            0 => return None,
            len if len < buffer.len() => {
                buffer.truncate(len);
                return dos_path(&buffer);
            }
            len => buffer.resize(len + 1, 0),
        }
    }
}
