//! How the command's process hands its seccomp listener to the recorder:
//! over a close-on-exec socket pair, as `SCM_RIGHTS`, between installing
//! the filter and `exec`. The send side runs after `fork`, so it only
//! makes system calls and uses no allocation.

use libc::{c_int, c_void};
use std::{
    io, mem,
    os::fd::{FromRawFd, OwnedFd},
};

/// The byte that comes with the listener.
const FILTERED: u8 = b'f';
/// The byte sent when the filter could not be installed.
const UNFILTERED: u8 = b'u';

/// Room for one `SCM_RIGHTS` message carrying one descriptor.
type ControlBuffer = [u64; 4];

pub(super) fn socket_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as c_int; 2];
    // SAFETY: `socketpair` writes two descriptors into `fds`, which this
    // function then owns.
    unsafe {
        if libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        ) != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok((OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])))
    }
}

/// Send `listener` through `socket`, or report that there is none when it
/// is negative.
pub(super) fn send(socket: c_int, listener: c_int) {
    let mut byte = if listener >= 0 { FILTERED } else { UNFILTERED };
    let mut control: ControlBuffer = [0; 4];
    let mut iov = libc::iovec { iov_base: (&raw mut byte).cast::<c_void>(), iov_len: 1 };
    // SAFETY: an all-zero `msghdr` is valid; the fields used are set below.
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &raw mut iov;
    message.msg_iovlen = 1;
    if listener >= 0 {
        // SAFETY: `control` has room for one descriptor's control message,
        // which `CMSG_FIRSTHDR` points into once the length is set.
        unsafe {
            message.msg_control = control.as_mut_ptr().cast::<c_void>();
            message.msg_controllen = libc::CMSG_SPACE(mem::size_of::<c_int>() as u32) as _;
            let header = libc::CMSG_FIRSTHDR(&raw const message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(mem::size_of::<c_int>() as u32) as _;
            libc::CMSG_DATA(header).cast::<c_int>().write_unaligned(listener);
        }
    }
    // SAFETY: `message` and everything it points at live across the call.
    unsafe {
        libc::sendmsg(socket, &raw const message, 0);
    }
}

/// The listener the command's process sent, `Ok(None)` when it reported
/// that it has none, and an error when it sent nothing.
pub(super) fn receive(socket: &OwnedFd) -> io::Result<Option<OwnedFd>> {
    use std::os::fd::AsRawFd;
    let mut byte = 0u8;
    let mut control: ControlBuffer = [0; 4];
    let mut iov = libc::iovec { iov_base: (&raw mut byte).cast::<c_void>(), iov_len: 1 };
    // SAFETY: an all-zero `msghdr` is valid; the fields used are set below.
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &raw mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast::<c_void>();
    message.msg_controllen = mem::size_of::<ControlBuffer>() as _;
    let received = loop {
        // SAFETY: `message` and the buffers it points at live across the
        // call.
        let received =
            unsafe { libc::recvmsg(socket.as_raw_fd(), &raw mut message, libc::MSG_CMSG_CLOEXEC) };
        if received >= 0 || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            break received;
        }
    };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }
    if received == 0 {
        return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
    }
    // SAFETY: the kernel filled in `message`; a control message, when
    // present, is an `SCM_RIGHTS` one carrying the descriptor sent.
    let listener = unsafe {
        let header = libc::CMSG_FIRSTHDR(&raw const message);
        if header.is_null() || (*header).cmsg_type != libc::SCM_RIGHTS {
            None
        } else {
            let fd = libc::CMSG_DATA(header).cast::<c_int>().read_unaligned();
            Some(OwnedFd::from_raw_fd(fd))
        }
    };
    Ok(listener.filter(|_| byte == FILTERED))
}
