use libc::{c_uint, sock_filter, sock_fprog};

#[cfg(target_arch = "x86_64")]
pub(super) const NATIVE_AUDIT_ARCH: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
pub(super) const NATIVE_AUDIT_ARCH: u32 = 0xC000_00B7;

/// System call numbers of the x32 ABI carry this bit on x86-64.
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;

/// A seccomp program that hands the listed system calls to the tracer and
/// lets every other one through. System calls of a foreign ABI (32-bit
/// compatibility calls, x32) are handed over too, so the tracer can notice
/// what it cannot decode rather than miss it.
///
/// `io_uring` performs file operations without any of the system calls
/// the tracer sees, so setting one up fails with `ENOSYS`, the error
/// programs already fall back from on kernels without it.
pub(super) struct Filter {
    instructions: Vec<sock_filter>,
}

impl Filter {
    pub(super) fn new(traced_syscalls: &[i64]) -> Self {
        let mut instructions = vec![
            load(SECCOMP_DATA_ARCH_OFFSET),
            jump_if_equal(NATIVE_AUDIT_ARCH, 1, 0),
            ret(libc::SECCOMP_RET_TRACE),
            load(SECCOMP_DATA_NR_OFFSET),
            jump_if_equal(libc::SYS_io_uring_setup as u32, 0, 1),
            ret(libc::SECCOMP_RET_ERRNO | libc::ENOSYS as c_uint),
        ];
        let foreign_abi_checks = usize::from(cfg!(target_arch = "x86_64"));
        let to_trace = |index: usize| {
            u8::try_from(traced_syscalls.len() + foreign_abi_checks - index)
                .expect("the traced system calls fit a BPF jump")
        };
        #[cfg(target_arch = "x86_64")]
        instructions.push(jump_if_at_least(X32_SYSCALL_BIT, to_trace(0)));
        for (index, number) in traced_syscalls.iter().enumerate() {
            let number = u32::try_from(*number).expect("system call numbers are positive");
            instructions.push(jump_if_equal(number, to_trace(index + foreign_abi_checks), 0));
        }
        instructions.push(ret(libc::SECCOMP_RET_ALLOW));
        instructions.push(ret(libc::SECCOMP_RET_TRACE));
        Filter { instructions }
    }

    /// Install the filter on the calling thread, which the thread's
    /// descendants inherit. Runs between `fork` and `exec`, so it only
    /// makes system calls.
    pub(super) fn install(&self) -> bool {
        let program = sock_fprog {
            len: u16::try_from(self.instructions.len()).expect("the filter fits a BPF program"),
            filter: self.instructions.as_ptr().cast_mut(),
        };
        // SAFETY: `prctl` reads `program` and the instructions it points
        // at, both alive for the duration of the call.
        unsafe {
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
                && libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &raw const program)
                    == 0
        }
    }
}

fn load(offset: u32) -> sock_filter {
    statement(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, offset)
}

fn ret(action: c_uint) -> sock_filter {
    statement(libc::BPF_RET | libc::BPF_K, action)
}

fn statement(code: u32, k: u32) -> sock_filter {
    sock_filter { code: code as u16, jt: 0, jf: 0, k }
}

fn jump_if_equal(value: u32, jt: u8, jf: u8) -> sock_filter {
    sock_filter { code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16, jt, jf, k: value }
}

#[cfg(target_arch = "x86_64")]
fn jump_if_at_least(value: u32, jt: u8) -> sock_filter {
    sock_filter { code: (libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K) as u16, jt, jf: 0, k: value }
}
