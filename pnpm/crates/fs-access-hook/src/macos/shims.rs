//! Entry points for the variadic `open` functions. Rust cannot define a
//! C-variadic function, and the `mode` that follows `O_CREAT` is variadic.
//! On x86-64 a variadic integer travels in the same register as a fixed
//! one, so the hook itself is the entry point. On arm64, Apple passes
//! variadic arguments on the stack: the entry loads the mode into the
//! register a fixed argument would use, then continues in the hook. A
//! call without a mode loads whatever the stack holds there, which the
//! original ignores without `O_CREAT`.

#[cfg(target_arch = "x86_64")]
pub(super) use super::files::{
    pnpm_open_hook as open_entry, pnpm_open_nocancel_hook as open_nocancel_entry,
    pnpm_openat_hook as openat_entry, pnpm_openat_nocancel_hook as openat_nocancel_entry,
};

#[cfg(target_arch = "aarch64")]
std::arch::global_asm!(
    ".globl _pnpm_open_entry",
    ".p2align 2",
    "_pnpm_open_entry:",
    "    ldr x2, [sp]",
    "    b _pnpm_open_hook",
    ".globl _pnpm_open_nocancel_entry",
    ".p2align 2",
    "_pnpm_open_nocancel_entry:",
    "    ldr x2, [sp]",
    "    b _pnpm_open_nocancel_hook",
    ".globl _pnpm_openat_entry",
    ".p2align 2",
    "_pnpm_openat_entry:",
    "    ldr x3, [sp]",
    "    b _pnpm_openat_hook",
    ".globl _pnpm_openat_nocancel_entry",
    ".p2align 2",
    "_pnpm_openat_nocancel_entry:",
    "    ldr x3, [sp]",
    "    b _pnpm_openat_nocancel_hook",
);

#[cfg(target_arch = "aarch64")]
unsafe extern "C" {
    #[link_name = "pnpm_open_entry"]
    pub(super) fn open_entry();
    #[link_name = "pnpm_open_nocancel_entry"]
    pub(super) fn open_nocancel_entry();
    #[link_name = "pnpm_openat_entry"]
    pub(super) fn openat_entry();
    #[link_name = "pnpm_openat_nocancel_entry"]
    pub(super) fn openat_nocancel_entry();
}
