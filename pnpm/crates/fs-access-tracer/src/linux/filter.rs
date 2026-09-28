use libc::{c_uint, sock_filter, sock_fprog};

#[cfg(target_arch = "x86_64")]
pub(super) const NATIVE_AUDIT_ARCH: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
pub(super) const NATIVE_AUDIT_ARCH: u32 = 0xC000_00B7;

/// System call numbers of the x32 ABI carry this bit on x86-64.
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

const NR_OFFSET: u32 = 0;
const ARCH_OFFSET: u32 = 4;

/// The offset of the low half of system call argument `index` in
/// `struct seccomp_data`, on a little-endian machine.
const fn argument_offset(index: u32) -> u32 {
    16 + 8 * index
}

/// A seccomp program that hands the listed system calls to the supervisor
/// and lets every other one through.
///
/// - System calls of a foreign ABI (32-bit compatibility calls, x32) are
///   handed over too, so the supervisor notices what it cannot decode
///   rather than miss it.
/// - A `stat` of a descriptor (`AT_EMPTY_PATH`) names no path, so it runs
///   without a round trip. Every `fstat` after an `open` is one.
/// - `io_uring` performs file operations without any of the system calls
///   the supervisor sees, so setting one up fails with `ENOSYS`, the error
///   programs already fall back from on kernels without it.
pub(super) struct Filter {
    instructions: Vec<sock_filter>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Label {
    Native,
    Allow,
    Notify,
    Refuse,
    FlagsAt(u32),
}

enum Instruction {
    Load(u32),
    Return(c_uint),
    JumpIfEqual(u32, Label),
    #[cfg(target_arch = "x86_64")]
    JumpIfAtLeast(u32, Label),
    /// Jump to the first label when any of the bits are set, else to the
    /// second.
    JumpIfAnySet(u32, Label, Label),
    Mark(Label),
}

impl Filter {
    /// `flag_exempt` lists the system calls that skip the round trip when
    /// the flags argument at the given index carries `AT_EMPTY_PATH`.
    pub(super) fn new(notified: &[i64], flag_exempt: &[(i64, u32)]) -> Self {
        let mut program = vec![
            Instruction::Load(ARCH_OFFSET),
            Instruction::JumpIfEqual(NATIVE_AUDIT_ARCH, Label::Native),
            Instruction::Return(libc::SECCOMP_RET_USER_NOTIF),
            Instruction::Mark(Label::Native),
            Instruction::Load(NR_OFFSET),
        ];
        #[cfg(target_arch = "x86_64")]
        program.push(Instruction::JumpIfAtLeast(X32_SYSCALL_BIT, Label::Notify));
        program.push(Instruction::JumpIfEqual(syscall(libc::SYS_io_uring_setup), Label::Refuse));
        for (number, index) in flag_exempt {
            program.push(Instruction::JumpIfEqual(syscall(*number), Label::FlagsAt(*index)));
        }
        for number in notified {
            program.push(Instruction::JumpIfEqual(syscall(*number), Label::Notify));
        }
        program.push(Instruction::Return(libc::SECCOMP_RET_ALLOW));
        let mut indexes: Vec<u32> = flag_exempt
            .iter()
            .map(|(_, index)| *index)
            .collect();
        indexes.sort_unstable();
        indexes.dedup();
        for index in indexes {
            program.extend([
                Instruction::Mark(Label::FlagsAt(index)),
                Instruction::Load(argument_offset(index)),
                Instruction::JumpIfAnySet(libc::AT_EMPTY_PATH as u32, Label::Allow, Label::Notify),
            ]);
        }
        program.extend([
            Instruction::Mark(Label::Allow),
            Instruction::Return(libc::SECCOMP_RET_ALLOW),
            Instruction::Mark(Label::Notify),
            Instruction::Return(libc::SECCOMP_RET_USER_NOTIF),
            Instruction::Mark(Label::Refuse),
            Instruction::Return(libc::SECCOMP_RET_ERRNO | libc::ENOSYS as c_uint),
        ]);
        Filter { instructions: assemble(&program) }
    }

    pub(super) fn program(&self) -> sock_fprog {
        sock_fprog {
            len: u16::try_from(self.instructions.len()).expect("the filter fits a BPF program"),
            filter: self.instructions.as_ptr().cast_mut(),
        }
    }
}

// SAFETY: the instructions are plain data the filter only reads.
unsafe impl Send for Filter {}
// SAFETY: as above.
unsafe impl Sync for Filter {}

fn syscall(number: i64) -> u32 {
    u32::try_from(number).expect("system call numbers are positive")
}

/// Resolve the labels into BPF's forward jump offsets.
fn assemble(program: &[Instruction]) -> Vec<sock_filter> {
    let mut positions: Vec<(Label, usize)> = Vec::new();
    let mut position = 0;
    for instruction in program {
        match instruction {
            Instruction::Mark(label) => positions.push((*label, position)),
            _ => position += 1,
        }
    }
    let target = |label: Label, from: usize| -> u8 {
        let (_, at) = positions
            .iter()
            .find(|(candidate, _)| *candidate == label)
            .expect("every jump target is marked");
        u8::try_from(at - from - 1).expect("the filter's jumps fit BPF's offsets")
    };
    let mut instructions = Vec::new();
    for instruction in program {
        let from = instructions.len();
        instructions.push(match *instruction {
            Instruction::Mark(_) => continue,
            Instruction::Load(offset) => {
                statement(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, offset)
            }
            Instruction::Return(action) => statement(libc::BPF_RET | libc::BPF_K, action),
            Instruction::JumpIfEqual(value, label) => {
                jump(libc::BPF_JEQ, value, target(label, from), 0)
            }
            #[cfg(target_arch = "x86_64")]
            Instruction::JumpIfAtLeast(value, label) => {
                jump(libc::BPF_JGE, value, target(label, from), 0)
            }
            Instruction::JumpIfAnySet(bits, set, unset) => {
                jump(libc::BPF_JSET, bits, target(set, from), target(unset, from))
            }
        });
    }
    instructions
}

fn statement(code: u32, k: u32) -> sock_filter {
    sock_filter { code: code as u16, jt: 0, jf: 0, k }
}

fn jump(condition: u32, k: u32, jt: u8, jf: u8) -> sock_filter {
    sock_filter { code: (libc::BPF_JMP | condition | libc::BPF_K) as u16, jt, jf, k }
}
