// gobuf_asm_amd64 — the three context-switch primitives, in assembly.
//
// Moved verbatim from `sched/gobuf.rs`. The `Gobuf` layout these read
// and write (7 callee-saved GPRs + sp + pc, no FP state, because SysV
// makes xmm caller-saved) is declared there and is amd64-shaped; an
// arm64 sibling needs a parallel struct, not a rename.
//
// Go: `runtime/asm_amd64.s` (`gogo`, `mcall`, `systemstack`).

use super::gobuf::Gobuf;
use core::arch::naked_asm;

/// `swap_context(from, to)` — symmetric two-context exchange.
///
/// Saves the current callee-saved register set (rsp, rbp, rbx,
/// r12-r15) into `*from`, loads `*to` into those same registers,
/// then `RET`s. Because PC lives at `[rsp]`, the RET pops the saved
/// PC from `*to`'s stack and jumps there.
///
/// Calling convention: `extern "C"` so SysV places `from` in `rdi`
/// and `to` in `rsi`. The function is naked — no Rust prologue or
/// epilogue. From Rust's perspective, calling this looks like a
/// regular `extern "C"` call that may take a long time to return,
/// since "return" can happen via a different `swap_context` call
/// from another stack.
///
/// Safety: caller must guarantee `from` and `to` point to valid
/// `Gobuf` instances and that `*to` either represents a previously
/// suspended context (saved by an earlier `swap_context`) or a
/// fresh context laid out by `make_context`. Failing these
/// preconditions corrupts the stack pointer and crashes the
/// process.
#[unsafe(naked)]
pub unsafe extern "C" fn swap_context(_from: *mut Gobuf, _to: *const Gobuf) {
    naked_asm!(
        // Save callee-saved registers into *from (rdi).
        "mov [rdi + 0x00], rsp",
        "mov [rdi + 0x08], rbp",
        "mov [rdi + 0x10], rbx",
        "mov [rdi + 0x18], r12",
        "mov [rdi + 0x20], r13",
        "mov [rdi + 0x28], r14",
        "mov [rdi + 0x30], r15",
        // Load callee-saved registers from *to (rsi). RSP last so
        // we don't disturb the rest of the load by pointing at
        // unfamiliar memory.
        "mov rbp, [rsi + 0x08]",
        "mov rbx, [rsi + 0x10]",
        "mov r12, [rsi + 0x18]",
        "mov r13, [rsi + 0x20]",
        "mov r14, [rsi + 0x28]",
        "mov r15, [rsi + 0x30]",
        "mov rsp, [rsi + 0x00]",
        // Resume target context — pops the saved PC from its
        // stack and jumps.
        "ret",
        // M18b-α phase C: mark the end of `swap_context`'s text so
        // the SIGURG preempt handler can refuse to inject when PC
        // falls anywhere inside this asm. SIGURG arriving mid-swap
        // (after `mov rsp, [rsi+0x00]` but before `ret`) would have
        // the kernel-saved RSP pointing at the *target* G's stack
        // while the target's user PC has not yet been popped — a
        // hijacked injection there would make the trampoline
        // resume at a non-PC byte and crash the worker.
        ".globl goish_swap_context_end",
        "goish_swap_context_end:",
        "int3",
    )
}

/// `gogo(buf)` — load `*buf` into registers and JMP to `buf.pc`.
///
/// Unlike `swap_context`, `gogo` has no save side: the caller is
/// expected to be on a context that won't be resumed (typically
/// `m.g0`'s scheduler stack, where the next iteration of `schedule()`
/// will overwrite this frame anyway).
///
/// **Why JMP, not RET.** Mirrors Go's `runtime·gogo`
/// (runtime/asm_amd64.s:404). RET would pop a PC from `[rsp]` —
/// requiring us to lay the resume PC on the target G's stack and to
/// adjust `gobuf.rsp` to point one slot below it. Under the SysV
/// red-zone rules (128 bytes below RSP are reserved scratch for the
/// resumed function), the slot we'd write would alias the target G's
/// red zone. JMP avoids that — `gobuf.pc` is loaded directly from
/// the gobuf via an indirect jump and the target's stack stays
/// untouched.
///
/// Calling convention: SysV places `buf` in `rdi`. The function is
/// naked and never returns to its caller (control transfers to
/// `buf.pc`). Used by `execute(g)` to enter the next runnable G.
///
/// Safety: caller must guarantee `buf` is a valid `Gobuf` whose `pc`
/// is a callable instruction (typically a goroutine entry or a
/// previously-saved resume point) and whose `sp` is correctly aligned
/// for the SysV ABI at that PC. Failing these preconditions crashes
/// the process.
#[unsafe(naked)]
pub unsafe extern "C" fn gogo(_buf: *const Gobuf) -> ! {
    naked_asm!(
        // Load callee-saved registers from *buf (rdi). RSP is loaded
        // last — JMP through the gobuf indirection works regardless
        // of order, but loading RSP last keeps the asm parallel to
        // `swap_context`.
        "mov rbp, [rdi + 0x08]",
        "mov rbx, [rdi + 0x10]",
        "mov r12, [rdi + 0x18]",
        "mov r13, [rdi + 0x20]",
        "mov r14, [rdi + 0x28]",
        "mov r15, [rdi + 0x30]",
        "mov rsp, [rdi + 0x00]",
        // JMP to *(buf + 0x38) — no PC popped from stack, no red
        // zone touched. Target executes with rsp == buf.sp.
        "jmp qword ptr [rdi + 0x38]",
        // M17b-ε β.2: end-marker for the SIGURG preempt handler's
        // PC-range filter. SIGURG landing inside this asm would
        // corrupt the resume.
        ".globl goish_gogo_end",
        "goish_gogo_end:",
        "int3",
    )
}

/// `mcall_asm(from, to, fn, arg)` — internal half of `mcall`.
///
/// Saves the current callee-saved registers, return PC, and SP into
/// `*from` (the caller G's gobuf). Then switches RSP to `(*to).sp`
/// (g0's stack pointer) and calls `fn(arg)`.
///
/// **Layout of the save side, parallel to Go's `runtime·mcall`
/// (asm_amd64.s:427):**
///
///   - `from.pc` = `[rsp]` at entry — the return address pushed by
///     the `call mcall_asm` instruction in the Rust wrapper.
///   - `from.sp` = `rsp + 8` at entry — the SP value the caller had
///     before the `call` (i.e., the SP a future `gogo(from)` should
///     restore to so that an implicit RET would return to `from.pc`).
///   - `from.bp` = `rbp` at entry.
///   - `from.{rbx, r12-r15}` = callee-saved regs at entry.
///
/// **Switch side:**
///
///   - `rsp` ← `(*to).sp`  (g0's stack)
///   - `rbp` ← `(*to).bp`  (g0's saved frame pointer)
///   - `rdi` ← `arg`        (first SysV arg)
///   - `call rdx`           (`fn(arg)`)
///
/// `fn` must be `-> !`. If it returns, the asm executes `ud2`.
///
/// Calling convention (SysV): rdi=from, rsi=to, rdx=fn, rcx=arg.
///
/// **Resume.** When something later calls `gogo(from)`, control
/// transfers to `from.pc` with `rsp = from.sp` and the saved
/// callee-saved registers — i.e., back into the Rust wrapper's
/// frame at the instruction after `call mcall_asm`. The wrapper then
/// returns normally to its caller (the user-visible `Gosched`,
/// `gopark`, etc. site).
///
/// **Why split mcall this way.** Go's mcall is a single asm primitive
/// because Go's calling convention exposes the current G via a
/// dedicated register (R14). Rust's calling convention does not, so
/// curg/g0 lookup happens in the Rust `mcall` wrapper before this
/// asm. The asm itself only handles the red-zone-safe save+switch.
#[unsafe(naked)]
pub unsafe extern "C" fn mcall_asm(
    _from: *mut Gobuf,
    _to: *const Gobuf,
    _fn: extern "C" fn(*mut crate::runtime::sched::g::G) -> !,
    _arg: *mut crate::runtime::sched::g::G,
) {
    naked_asm!(
        // Save callee-saved registers FIRST, before any clobber.
        "mov [rdi + 0x10], rbx",
        "mov [rdi + 0x18], r12",
        "mov [rdi + 0x20], r13",
        "mov [rdi + 0x28], r14",
        "mov [rdi + 0x30], r15",
        "mov [rdi + 0x08], rbp",
        // Save caller's PC (return address at [rsp]) and the SP
        // value the caller had pre-CALL (rsp + 8). Mirrors Go's
        // `MOVQ 0(SP), BX` / `LEAQ fn+0(FP), BX`.
        "mov rax, [rsp]",
        "mov [rdi + 0x38], rax",
        "lea rax, [rsp + 8]",
        "mov [rdi + 0x00], rax",
        // Switch to g0 stack.
        "mov rsp, [rsi + 0x00]",
        "mov rbp, [rsi + 0x08]",
        // Move fn arg into rdi (first SysV arg).
        "mov rdi, rcx",
        // Call fn(arg). CALL pushes return address, leaving rsp
        // 8-mod-16 aligned at fn entry — correct per SysV.
        "call rdx",
        // fn is -> !; if it returns, abort.
        "ud2",
        ".globl goish_mcall_end",
        "goish_mcall_end:",
        "int3",
    )
}
