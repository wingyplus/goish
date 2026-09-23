// gobuf_asm_arm64 — the saved register file and the three context-switch
// primitives, for AAPCS64. Shared by linux/arm64 and darwin/arm64: the
// register convention is the architecture's, and neither OS changes it
// (Apple's variant differs in varargs and x18, and this file touches
// neither).
//
// Go: `runtime/asm_arm64.s` (`gogo`, `mcall`), `runtime/sys_arm64.go`
// (`gostartcall`).
//
// ─── Why this is a restructure of the amd64 file, not a transliteration
//
//   * **The return address is in `x30`, not on the stack.** amd64's
//     `swap_context` resumes by `ret` popping a PC off the target stack,
//     and `make_context_gogo` parks the goexit address in a stack slot.
//     Here both live in the `Gobuf`: `pc` is where to branch, `lr` is
//     what `x30` holds when we get there. A fresh G is `pc = entry`,
//     `lr = goexit_trampoline`, `sp = stack_top` — Go's `gostartcall`
//     does exactly this (`buf.lr = buf.pc; buf.pc = fn`), with no slot
//     written on the new stack at all.
//   * **`d8`–`d15` are callee-saved** (their low 64 bits). SysV has no
//     such registers, which is why the amd64 `Gobuf` carries no FP state.
//     A switch that dropped them would corrupt float state in whatever
//     Rust frame resumes, with no crash to point at.
//   * **More than Go saves.** Go's `mcall` stores only sp, fp and pc,
//     because Go's own ABI has no callee-saved registers. goish's
//     `mcall_asm`/`swap_context` are entered from Rust through
//     `extern "C"`, so AAPCS64 obliges them to hand back x19–x28, x29,
//     x30 and d8–d15 intact — and "handing back" happens in a later
//     `gogo`, so all of them go in the `Gobuf`.
//   * **`x18` is never touched.** It is the platform register — reserved
//     outright on Darwin (`runtime/mkpreempt.go`: "R18 is not used,
//     skip").
//   * **`sp` is 16-byte aligned at every instant**, not just at call
//     sites — AAPCS64 requires it wherever `sp` is used to access
//     memory, and the architecture can trap a misaligned `sp` access
//     outright. Every `sp` this file installs comes from a 16-aligned
//     `stack_top` or a previously valid `sp`.
//   * **No red zone**, so none of amd64 `gogo`'s JMP-to-avoid-it
//     reasoning applies; branching through `pc` is simply how resume
//     works when the return address is a register.

use core::arch::naked_asm;

/// The saved register file. `rsp` and `pc` keep the amd64 names because
/// shared code reads them (`g0`'s stack top in `G::new_g0`, the
/// `panic_recover.rsp != 0` "armed" test); everything else is
/// asm-only.
///
///   off   field     register
///   0x00  rsp       sp
///   0x08  pc        branch target on resume
///   0x10  fp        x29
///   0x18  lr        x30 on resume
///   0x20  x19..x28  (10 × 8)
///   0x70  d8..d15   (8 × 8)
///   0xb0  — size
#[repr(C)]
#[derive(Default)]
pub struct Gobuf {
    pub rsp: u64,
    pub pc: u64,
    pub fp: u64,
    pub lr: u64,
    pub x: [u64; 10],
    pub d: [u64; 8],
}

const _: () = {
    assert!(core::mem::offset_of!(Gobuf, rsp) == 0x00);
    assert!(core::mem::offset_of!(Gobuf, pc) == 0x08);
    assert!(core::mem::offset_of!(Gobuf, fp) == 0x10);
    assert!(core::mem::offset_of!(Gobuf, lr) == 0x18);
    assert!(core::mem::offset_of!(Gobuf, x) == 0x20);
    assert!(core::mem::offset_of!(Gobuf, d) == 0x70);
    assert!(core::mem::size_of::<Gobuf>() == 0xb0);
};

impl Gobuf {
    pub const fn new() -> Self {
        Gobuf { rsp: 0, pc: 0, fp: 0, lr: 0, x: [0; 10], d: [0; 8] }
    }
}

/// Lay out `gobuf` so a `gogo` or `swap_context` into it enters `entry`
/// on the stack ending at `stack_top`, with `x30 = goexit_trampoline` in
/// case `entry` ever returns. Go: `gostartcall`.
///
/// One function serves both of the amd64 file's layouts, because here
/// they are the same: nothing is written to the new stack, so there is
/// no difference between "`ret` pops the entry" and "`jmp` to the
/// entry" to encode.
///
/// Safety: `stack_top` must be 16-byte aligned and the top of a
/// writable stack; `entry` must be a valid `extern "C" fn() -> !`.
pub unsafe fn make_context_gogo(gobuf: &mut Gobuf, stack_top: usize, entry: extern "C" fn() -> !) {
    debug_assert!(stack_top % 16 == 0, "stack_top not 16-byte aligned");
    *gobuf = Gobuf::new();
    gobuf.rsp = stack_top as u64;
    gobuf.pc = entry as usize as u64;
    gobuf.lr = super::gobuf::goexit_trampoline as *const () as usize as u64;
    // fp = 0 terminates frame-pointer walks at the G's first frame.
}

/// See `make_context_gogo` — identical on this architecture.
pub unsafe fn make_context(gobuf: &mut Gobuf, stack_top: usize, entry: extern "C" fn() -> !) {
    make_context_gogo(gobuf, stack_top, entry)
}

// The end-of-primitive labels the SIGURG handler's PC filter compares
// against (`runtime/preempt.rs` declares them as `extern "C"` symbols).
// A C-level symbol carries a leading underscore on Mach-O and none on
// ELF, so the label has to be spelled per OS to be the symbol Rust
// asks the linker for.
#[cfg(target_os = "macos")]
macro_rules! csym {
    ($s:literal) => { concat!("_", $s) };
}
#[cfg(not(target_os = "macos"))]
macro_rules! csym {
    ($s:literal) => { $s };
}

/// `swap_context(from, to)` — save the callee-saved state into `*from`,
/// resume `*to`. From the caller's side it is a call that returns
/// whenever something later resumes `*from`.
///
/// The resume point saved is the return address (`x30`): `pc` and `lr`
/// both get it, so resuming branches back into the caller with `x30`
/// as it expects.
#[unsafe(naked)]
pub unsafe extern "C" fn swap_context(_from: *mut super::gobuf::Gobuf, _to: *const super::gobuf::Gobuf) {
    naked_asm!(
        // ── save into *from (x0) ──
        "mov x9, sp",
        "str x9, [x0, #0x00]",
        "str x30, [x0, #0x08]",
        "stp x29, x30, [x0, #0x10]",
        "stp x19, x20, [x0, #0x20]",
        "stp x21, x22, [x0, #0x30]",
        "stp x23, x24, [x0, #0x40]",
        "stp x25, x26, [x0, #0x50]",
        "stp x27, x28, [x0, #0x60]",
        "stp d8, d9, [x0, #0x70]",
        "stp d10, d11, [x0, #0x80]",
        "stp d12, d13, [x0, #0x90]",
        "stp d14, d15, [x0, #0xa0]",
        // ── load *to (x1) and branch ──
        "ldp d8, d9, [x1, #0x70]",
        "ldp d10, d11, [x1, #0x80]",
        "ldp d12, d13, [x1, #0x90]",
        "ldp d14, d15, [x1, #0xa0]",
        "ldp x19, x20, [x1, #0x20]",
        "ldp x21, x22, [x1, #0x30]",
        "ldp x23, x24, [x1, #0x40]",
        "ldp x25, x26, [x1, #0x50]",
        "ldp x27, x28, [x1, #0x60]",
        "ldp x29, x30, [x1, #0x10]",
        "ldr x16, [x1, #0x08]",
        "ldr x9, [x1, #0x00]",
        "mov sp, x9",
        "br x16",
        concat!(".globl ", csym!("goish_swap_context_end")),
        concat!(csym!("goish_swap_context_end"), ":"),
        "brk #0x1",
    )
}

/// `gogo(buf)` — load `*buf` and branch to `buf.pc`. No save side; the
/// caller's context (normally a g0 frame in `schedule`) is abandoned.
/// Go: `gogo<>` — sp, fp, lr from the gobuf, then `B (pc)`.
#[unsafe(naked)]
pub unsafe extern "C" fn gogo(_buf: *const super::gobuf::Gobuf) -> ! {
    naked_asm!(
        "ldp d8, d9, [x0, #0x70]",
        "ldp d10, d11, [x0, #0x80]",
        "ldp d12, d13, [x0, #0x90]",
        "ldp d14, d15, [x0, #0xa0]",
        "ldp x19, x20, [x0, #0x20]",
        "ldp x21, x22, [x0, #0x30]",
        "ldp x23, x24, [x0, #0x40]",
        "ldp x25, x26, [x0, #0x50]",
        "ldp x27, x28, [x0, #0x60]",
        "ldp x29, x30, [x0, #0x10]",
        "ldr x16, [x0, #0x08]",
        "ldr x9, [x0, #0x00]",
        "mov sp, x9",
        "br x16",
        concat!(".globl ", csym!("goish_gogo_end")),
        concat!(csym!("goish_gogo_end"), ":"),
        "brk #0x1",
    )
}

/// `mcall_asm(from, to, fn, arg)` — save the calling G's state into
/// `*from`, switch to `(*to).rsp` (g0's stack) and call `fn(arg)`.
///
/// Go: `runtime·mcall` — save sp, fp and `LR` as the resume pc, switch
/// to g0's `sched.sp`, **clear the frame pointer** ("caller may execute
/// on another M"), call `fn`. `fn` is `-> !`; if it returns, `brk`.
///
/// Resuming `*from` later (`gogo`) branches to the instruction after
/// the `bl mcall_asm` in the Rust `mcall` wrapper, with every
/// callee-saved register as the wrapper left it.
#[unsafe(naked)]
pub unsafe extern "C" fn mcall_asm(
    _from: *mut super::gobuf::Gobuf,
    _to: *const super::gobuf::Gobuf,
    _fn: extern "C" fn(*mut crate::runtime::sched::g::G) -> !,
    _arg: *mut crate::runtime::sched::g::G,
) {
    naked_asm!(
        // ── save into *from (x0) ──
        "mov x9, sp",
        "str x9, [x0, #0x00]",
        "str x30, [x0, #0x08]",
        "stp x29, x30, [x0, #0x10]",
        "stp x19, x20, [x0, #0x20]",
        "stp x21, x22, [x0, #0x30]",
        "stp x23, x24, [x0, #0x40]",
        "stp x25, x26, [x0, #0x50]",
        "stp x27, x28, [x0, #0x60]",
        "stp d8, d9, [x0, #0x70]",
        "stp d10, d11, [x0, #0x80]",
        "stp d12, d13, [x0, #0x90]",
        "stp d14, d15, [x0, #0xa0]",
        // ── switch to g0 and call fn(arg) ──
        "ldr x9, [x1, #0x00]",
        "mov sp, x9",
        "mov x29, xzr",
        "mov x0, x3",
        "blr x2",
        concat!(".globl ", csym!("goish_mcall_end")),
        concat!(csym!("goish_mcall_end"), ":"),
        "brk #0x2",
    )
}
