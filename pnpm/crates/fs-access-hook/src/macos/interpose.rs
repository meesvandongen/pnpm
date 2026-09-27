//! dyld's interposing: a `(replacement, original)` pair in the
//! `__DATA,__interpose` section makes every other image's calls to
//! `original` go to `replacement`. The dylib's own calls are not
//! interposed, so a replacement calls the original by its name.

use std::ffi::c_void;

#[repr(C)]
pub(super) struct Entry {
    pub(super) replacement: *const c_void,
    pub(super) original: *const c_void,
}

// SAFETY: the entries are read-only data that dyld reads at load time.
unsafe impl Sync for Entry {}

/// Interpose `$original` with `$replacement`.
macro_rules! interpose {
    ($replacement:path => $original:path) => {
        const _: () = {
            #[used]
            #[unsafe(link_section = "__DATA,__interpose")]
            static ENTRY: $crate::macos::interpose::Entry = $crate::macos::interpose::Entry {
                replacement: $replacement as *const ::std::ffi::c_void,
                original: $original as *const ::std::ffi::c_void,
            };
        };
    };
}
pub(super) use interpose;
