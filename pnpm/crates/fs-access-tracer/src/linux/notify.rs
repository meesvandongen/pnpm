//! The seccomp listener: receiving a notified system call and letting it
//! continue.

use libc::c_void;
use std::{
    io, mem,
    os::fd::{AsRawFd, OwnedFd},
};

/// `SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP` from `<linux/seccomp.h>` (Linux
/// 6.6), which libc does not define yet.
const SYNC_WAKE_UP: u64 = 1;

/// The sizes the running kernel uses for the notification structures,
/// which may be larger than the ones libc was built against.
#[derive(Clone, Copy)]
pub(super) struct Sizes {
    notification: usize,
    response: usize,
}

impl Sizes {
    pub(super) fn query() -> io::Result<Sizes> {
        // SAFETY: an all-zero `seccomp_notif_sizes` is valid, and the
        // kernel writes the sizes into it.
        let mut sizes: libc::seccomp_notif_sizes = unsafe { mem::zeroed() };
        // SAFETY: `SECCOMP_GET_NOTIF_SIZES` writes into `sizes`, which
        // lives across the call.
        let result = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_GET_NOTIF_SIZES,
                0,
                (&raw mut sizes).cast::<c_void>(),
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Sizes {
            notification: usize::from(sizes.seccomp_notif)
                .max(mem::size_of::<libc::seccomp_notif>()),
            response: usize::from(sizes.seccomp_notif_resp)
                .max(mem::size_of::<libc::seccomp_notif_resp>()),
        })
    }
}

/// A notified system call, as the kernel describes it.
pub(super) struct Notification {
    pub(super) id: u64,
    pub(super) tid: libc::pid_t,
    pub(super) arch: u32,
    pub(super) number: i64,
    pub(super) args: [u64; 6],
}

pub(super) enum Wait {
    Ready,
    /// Every process the filter applies to is gone.
    HungUp,
}

pub(super) struct Listener {
    fd: OwnedFd,
    notification: Vec<u64>,
    response: Vec<u64>,
}

impl Listener {
    pub(super) fn new(fd: OwnedFd, sizes: Sizes) -> Self {
        Listener {
            fd,
            notification: vec![0; sizes.notification.div_ceil(8)],
            response: vec![0; sizes.response.div_ceil(8)],
        }
    }

    /// Ask the kernel to switch straight to the thread receiving a
    /// notification, on the notifying thread's CPU. Kernels before 6.6
    /// wake it the ordinary way, which costs more per call.
    pub(super) fn prefer_synchronous_wake_up(&self) {
        // SAFETY: `SECCOMP_IOCTL_NOTIF_SET_FLAGS` takes the flags by value.
        unsafe {
            libc::ioctl(self.fd.as_raw_fd(), libc::SECCOMP_IOCTL_NOTIF_SET_FLAGS, SYNC_WAKE_UP);
        }
    }

    pub(super) fn wait(&self) -> io::Result<Wait> {
        let mut poll = libc::pollfd { fd: self.fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        loop {
            // SAFETY: `poll` lives across the call.
            if unsafe { libc::poll(&raw mut poll, 1, -1) } >= 0 {
                break;
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
        if poll.revents & libc::POLLIN != 0 {
            return Ok(Wait::Ready);
        }
        Ok(Wait::HungUp)
    }

    /// The next notification, or `None` when the one that was pending is
    /// gone (its thread was killed, or another thread received it).
    pub(super) fn receive(&mut self) -> io::Result<Option<Notification>> {
        self.notification.fill(0);
        // SAFETY: the buffer is zeroed, as the kernel requires, and at
        // least as large as the kernel's `struct seccomp_notif`.
        let result = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                libc::SECCOMP_IOCTL_NOTIF_RECV,
                self.notification.as_mut_ptr(),
            )
        };
        if result != 0 {
            let error = io::Error::last_os_error();
            return match error.raw_os_error() {
                Some(libc::ENOENT | libc::EINTR) => Ok(None),
                _ => Err(error),
            };
        }
        // SAFETY: the kernel wrote a `seccomp_notif` at the start of the
        // buffer, which is aligned for it.
        let raw = unsafe { &*self.notification.as_ptr().cast::<libc::seccomp_notif>() };
        Ok(Some(Notification {
            id: raw.id,
            tid: raw.pid as libc::pid_t,
            arch: raw.data.arch,
            number: i64::from(raw.data.nr),
            args: raw.data.args,
        }))
    }

    /// Let the notified call run as the process made it.
    pub(super) fn resume(&mut self, id: u64) {
        self.response.fill(0);
        // SAFETY: the buffer is zeroed and at least as large as the
        // kernel's `struct seccomp_notif_resp`, and aligned for it.
        unsafe {
            let response = &mut *self.response.as_mut_ptr().cast::<libc::seccomp_notif_resp>();
            response.id = id;
            response.flags = libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32;
            // A call whose thread was killed meanwhile fails with ENOENT,
            // which leaves nothing to resume.
            libc::ioctl(
                self.fd.as_raw_fd(),
                libc::SECCOMP_IOCTL_NOTIF_SEND,
                self.response.as_mut_ptr(),
            );
        }
    }

    /// Whether notification `id` is still waiting for its response, which
    /// tells a thread that died meanwhile from a path that cannot be read.
    pub(super) fn is_pending(&self, id: u64) -> bool {
        let mut id = id;
        // SAFETY: `SECCOMP_IOCTL_NOTIF_ID_VALID` reads the id from `id`.
        unsafe {
            libc::ioctl(self.fd.as_raw_fd(), libc::SECCOMP_IOCTL_NOTIF_ID_VALID, &raw mut id) == 0
        }
    }
}
