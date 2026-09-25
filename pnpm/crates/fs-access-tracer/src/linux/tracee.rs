use libc::{c_int, c_void, pid_t};
use std::{
    ffi::OsString,
    fs, io, mem,
    os::unix::ffi::OsStringExt,
    path::{Path, PathBuf},
};

const PTRACE_GET_SYSCALL_INFO: u32 = 0x420e;
const PTRACE_SYSCALL_INFO_EXIT: u8 = 2;
const PTRACE_SYSCALL_INFO_SECCOMP: u8 = 3;
const PATH_MAX: usize = 4096;
const PAGE_SIZE: usize = 4096;

/// `struct ptrace_syscall_info` from `<linux/ptrace.h>`, with the union
/// flattened into the words its members occupy.
#[repr(C)]
#[derive(Default)]
struct RawSyscallInfo {
    op: u8,
    pad: [u8; 3],
    arch: u32,
    instruction_pointer: u64,
    stack_pointer: u64,
    data: [u64; 8],
}

/// A system call a tracee stopped at, as `PTRACE_GET_SYSCALL_INFO` reports
/// it.
pub(super) enum SyscallStop {
    /// Stopped by the seccomp filter before the call runs.
    Entry {
        arch: u32,
        number: i64,
        args: [u64; 6],
    },
    Exit {
        failed: bool,
    },
}

/// One stopped thread of the traced process tree.
#[derive(Clone, Copy)]
pub(super) struct Tracee {
    pub(super) tid: pid_t,
}

impl Tracee {
    /// The system call the thread is stopped at, or `None` when the kernel
    /// cannot say (a kernel older than 5.3).
    pub(super) fn syscall_stop(self) -> Option<SyscallStop> {
        let mut info = RawSyscallInfo::default();
        // SAFETY: the kernel writes at most `size_of::<RawSyscallInfo>()`
        // bytes into `info`, which lives across the call.
        let written = unsafe {
            libc::ptrace(
                PTRACE_GET_SYSCALL_INFO as _,
                self.tid,
                mem::size_of::<RawSyscallInfo>(),
                (&raw mut info).cast::<c_void>(),
            )
        };
        if written <= 0 {
            return None;
        }
        match info.op {
            PTRACE_SYSCALL_INFO_SECCOMP => Some(SyscallStop::Entry {
                arch: info.arch,
                number: info.data[0] as i64,
                args: [
                    info.data[1],
                    info.data[2],
                    info.data[3],
                    info.data[4],
                    info.data[5],
                    info.data[6],
                ],
            }),
            // `is_error` is the byte after the 64-bit return value.
            PTRACE_SYSCALL_INFO_EXIT => {
                Some(SyscallStop::Exit { failed: info.data[1] & 0xff != 0 })
            }
            _ => None,
        }
    }

    /// The path a `*at` system call names through `dirfd` and the
    /// NUL-terminated string at `address`, made absolute. `None` for an
    /// empty name (`AT_EMPTY_PATH` operates on `dirfd` itself) or one that
    /// cannot be read.
    pub(super) fn path_at(self, dirfd: c_int, address: u64) -> Option<PathBuf> {
        let name = PathBuf::from(OsString::from_vec(self.read_c_string(address)?));
        if name.as_os_str().is_empty() {
            return None;
        }
        if name.is_absolute() {
            return Some(name);
        }
        let base = if dirfd == libc::AT_FDCWD { self.cwd()? } else { self.fd_path(dirfd)? };
        Some(base.join(name))
    }

    /// The path an open descriptor refers to, when it refers to one.
    pub(super) fn fd_path(self, fd: c_int) -> Option<PathBuf> {
        self.proc_link(&format!("fd/{fd}"))
    }

    /// The executable the thread's process runs.
    pub(super) fn executable(self) -> Option<PathBuf> {
        self.proc_link("exe")
    }

    pub(super) fn read_u64(self, address: u64) -> Option<u64> {
        let mut bytes = [0u8; 8];
        (self.read_memory(address, &mut bytes)? == bytes.len()).then(|| u64::from_ne_bytes(bytes))
    }

    fn cwd(self) -> Option<PathBuf> {
        self.proc_link("cwd")
    }

    fn proc_link(self, name: &str) -> Option<PathBuf> {
        let target = fs::read_link(Path::new("/proc").join(self.tid.to_string()).join(name)).ok()?;
        target.is_absolute().then_some(target)
    }

    fn read_c_string(self, address: u64) -> Option<Vec<u8>> {
        let mut buffer = vec![0u8; PATH_MAX];
        let read = self.read_memory(address, &mut buffer)?;
        let length = buffer[..read]
            .iter()
            .position(|byte| *byte == 0)?;
        buffer.truncate(length);
        Some(buffer)
    }

    /// Copy tracee memory into `buffer`, stopping early at the first
    /// unmapped page. Returns how many bytes were copied.
    fn read_memory(self, address: u64, buffer: &mut [u8]) -> Option<usize> {
        match self.read_memory_vectored(address, buffer) {
            Ok(read) => Some(read),
            Err(_) => self.peek_memory(address, buffer),
        }
    }

    fn read_memory_vectored(self, address: u64, buffer: &mut [u8]) -> io::Result<usize> {
        let first_page = (PAGE_SIZE - (address as usize % PAGE_SIZE)).min(buffer.len());
        let remote = [
            libc::iovec { iov_base: address as *mut c_void, iov_len: first_page },
            libc::iovec {
                iov_base: (address as usize + first_page) as *mut c_void,
                iov_len: buffer.len() - first_page,
            },
        ];
        let local = libc::iovec { iov_base: buffer.as_mut_ptr().cast(), iov_len: buffer.len() };
        // SAFETY: `local` covers exactly `buffer`, and the kernel validates
        // the remote ranges. Splitting at the page boundary lets a string
        // that ends just before an unmapped page be read up to it.
        let read =
            unsafe { libc::process_vm_readv(self.tid, &raw const local, 1, remote.as_ptr(), 2, 0) };
        if read < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(read as usize)
    }

    /// Word-by-word fallback for sandboxes that forbid `process_vm_readv`.
    fn peek_memory(self, address: u64, buffer: &mut [u8]) -> Option<usize> {
        let word_size = mem::size_of::<libc::c_long>();
        let mut read = 0;
        while read < buffer.len() {
            let word = self.peek_word(address + read as u64)?;
            let bytes = word.to_ne_bytes();
            let take = word_size.min(buffer.len() - read);
            buffer[read..read + take].copy_from_slice(&bytes[..take]);
            read += take;
            if bytes[..take].contains(&0) {
                break;
            }
        }
        Some(read)
    }

    fn peek_word(self, address: u64) -> Option<libc::c_long> {
        // SAFETY: errno is cleared first because `PTRACE_PEEKDATA` returns
        // the word itself, so -1 is only an error when errno says so.
        unsafe {
            *libc::__errno_location() = 0;
            let word = libc::ptrace(
                libc::PTRACE_PEEKDATA as _,
                self.tid,
                address as *mut c_void,
                std::ptr::null_mut::<c_void>(),
            );
            (*libc::__errno_location() == 0).then_some(word)
        }
    }
}
