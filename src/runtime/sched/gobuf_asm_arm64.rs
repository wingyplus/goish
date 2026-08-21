// gobuf_asm_arm64 — the three context-switch primitives. **Not yet
// implemented; this is milestone M5.**
//
// These are deliberately aborts rather than a transliteration of the
// amd64 bodies, because AAPCS64 differs from SysV in ways that make a
// mechanical translation silently wrong:
//
//   * **The return address is in `x30`, not on the stack.** amd64's
//     `swap_context` restores PC by arranging for `ret` to pop it off
//     the target stack, and `gogo` jumps through the gobuf to dodge the
//     red zone. Neither shape survives; both need restructuring.
//   * **`d8`–`d15` are callee-saved.** SysV has no equivalent — it makes
//     every xmm register caller-saved, which is exactly why the amd64
//     `Gobuf` carries no FP state at all. Omitting them here would
//     corrupt float state with no crash to point at.
//   * **`x18` must never be touched** (`runtime/mkpreempt.go:573` —
//     "R18 is not used, skip"), and there is no red zone.
//
// So arm64 needs a parallel `Gobuf` of 22 slots (x19–x28, x29, x30, sp,
// pc, d8–d15) rather than the amd64 struct with renamed fields, and the
// three functions below have to be written against it.
//
// Go: `runtime/asm_arm64.s` (`gogo`, `mcall`, `systemstack`),
// `runtime/stubs_arm64.go`.

use super::gobuf::Gobuf;

/// Abort with a message naming the milestone that will supply the real
/// implementation. Reached only if the scheduler is brought up on
/// arm64 before M5 lands — the staged `__goish_rt0` boot path does not
/// reach any of these.
#[cold]
#[inline(never)]
fn m5(what: &[u8]) -> ! {
    let msg = b"goish: arm64 context switch is not implemented yet (M5): ";
    crate::syscall::Write(crate::syscall::STDERR, msg.as_ptr(), msg.len());
    crate::syscall::Write(crate::syscall::STDERR, what.as_ptr(), what.len());
    crate::syscall::Write(crate::syscall::STDERR, b"\n".as_ptr(), 1);
    crate::syscall::Exit(2)
}

/// See `gobuf_asm_amd64::swap_context`. M5.
#[allow(unused_variables)]
pub unsafe extern "C" fn swap_context(_from: *mut Gobuf, _to: *const Gobuf) {
    m5(b"swap_context")
}

/// See `gobuf_asm_amd64::gogo`. M5.
#[allow(unused_variables)]
pub unsafe extern "C" fn gogo(_buf: *const Gobuf) -> ! {
    m5(b"gogo")
}

/// See `gobuf_asm_amd64::mcall_asm`. M5.
#[allow(unused_variables)]
pub unsafe extern "C" fn mcall_asm(
    _from: *mut Gobuf,
    _to: *const Gobuf,
    _fn: extern "C" fn(*mut crate::runtime::sched::g::G) -> !,
    _arg: *mut crate::runtime::sched::g::G,
) {
    m5(b"mcall_asm")
}

// The SIGURG handler refuses to inject a preempt when the interrupted PC
// falls inside one of the context-switch primitives — a half-switched SP
// would crash the trampoline. It finds those ranges by comparing against
// end-marker symbols the amd64 `naked_asm!` blocks define inline
// (`goish_swap_context_end` and friends in `gobuf_asm_amd64.rs`).
//
// The stubs above are ordinary Rust functions with no such labels, so
// the markers are defined here instead, all at one address. Every range
// check then compares a PC against an empty interval and answers false —
// which is the truth: until M5 there is no arm64 context-switch asm to
// be inside. M5 replaces this block with the real in-body labels.
core::arch::global_asm!(
    ".globl goish_swap_context_end",
    "goish_swap_context_end:",
    ".globl goish_gogo_end",
    "goish_gogo_end:",
    ".globl goish_mcall_end",
    "goish_mcall_end:",
    "    ret",
);
