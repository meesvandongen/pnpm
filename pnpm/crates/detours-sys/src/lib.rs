//! Bindings to the parts of [Microsoft Detours](https://github.com/microsoft/Detours)
//! that pnpm's file access recorder uses: hooking functions in the current
//! process, and loading a DLL into a process it starts. Empty on targets
//! other than Windows.

#[cfg(windows)]
mod bindings;
#[cfg(windows)]
pub use bindings::*;
