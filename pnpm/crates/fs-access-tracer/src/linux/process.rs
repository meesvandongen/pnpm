use libc::{c_int, c_void, pid_t};
use std::{
    ffi::OsString,
    fs, io,
    os::unix::{ffi::OsStringExt, fs::FileExt},
    path::{Path, PathBuf},
};

const PATH_MAX: usize = 4096;
const PAGE_SIZE: usize = 4096;

/// A thread of the recorded process tree, blocked in the system call the
/// supervisor is handling.
#[derive(Clone, Copy)]
pub(super) struct Process {
    pub(super) tid: pid_t,
}

impl Process {
    /// The path a `*at` system call names through `dirfd` and the
    /// NUL-terminated string at `address`, made absolute. `Ok(None)` for an
    /// empty name (`AT_EMPTY_PATH` operates on `dirfd` itself), and `Err`
    /// when the name or the directory it is relative to cannot be read.
    pub(super) fn path_at(self, dirfd: c_int, address: u64) -> Result<Option<PathBuf>, ()> {
        let name = PathBuf::from(OsString::from_vec(self.read_c_string(address).ok_or(())?));
        if name.as_os_str().is_empty() {
            return Ok(None);
        }
        if name.is_absolute() {
            return Ok(Some(name));
        }
        let base = if dirfd == libc::AT_FDCWD { self.cwd() } else { self.fd_path(dirfd) };
        Ok(Some(base.ok_or(())?.join(name)))
    }

    /// The path an open descriptor refers to, when it refers to one.
    pub(super) fn fd_path(self, fd: c_int) -> Option<PathBuf> {
        self.proc_link(&format!("fd/{fd}"))
    }

    pub(super) fn read_u64(self, address: u64) -> Option<u64> {
        let mut bytes = [0u8; 8];
        (self.read_memory(address, &mut bytes)? == bytes.len()).then(|| u64::from_ne_bytes(bytes))
    }

    fn cwd(self) -> Option<PathBuf> {
        self.proc_link("cwd")
    }

    fn proc_link(self, name: &str) -> Option<PathBuf> {
        let target = fs::read_link(self.proc_path(name)).ok()?;
        target.is_absolute().then_some(target)
    }

    fn proc_path(self, name: &str) -> PathBuf {
        Path::new("/proc").join(self.tid.to_string()).join(name)
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

    /// Copy the thread's memory into `buffer`, stopping early at the first
    /// unmapped page. Returns how many bytes were copied.
    fn read_memory(self, address: u64, buffer: &mut [u8]) -> Option<usize> {
        match self.read_memory_vectored(address, buffer) {
            Ok(read) => Some(read),
            Err(_) => self.read_proc_mem(address, buffer),
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

    /// Fallback for sandboxes that forbid `process_vm_readv`, reading up to
    /// the end of the first page before extending into the next.
    fn read_proc_mem(self, address: u64, buffer: &mut [u8]) -> Option<usize> {
        let memory = fs::File::open(self.proc_path("mem")).ok()?;
        let first_page = (PAGE_SIZE - (address as usize % PAGE_SIZE)).min(buffer.len());
        let read = memory
            .read_at(&mut buffer[..first_page], address)
            .ok()?;
        if read < first_page || buffer[..read].contains(&0) {
            return Some(read);
        }
        let rest = memory
            .read_at(&mut buffer[first_page..], address + first_page as u64)
            .unwrap_or(0);
        Some(read + rest)
    }
}
