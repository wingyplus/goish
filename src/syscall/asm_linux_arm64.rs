// asm_linux_arm64 — whole functions written in assembly.
//
// Two things differ from amd64 in kind, not in spelling.
//
// **There is no sigreturn trampoline.** Go: `runtime/os_linux.go:478-487`
// sets `_SA_RESTORER` in `sa_flags` unconditionally, but populates
// `sa_restorer` only under `if GOARCH == "386" || GOARCH == "amd64"`,
// with the comment *"Although Linux manpage says sa_restorer element is
// obsolete and should not be used. x86_64 kernel requires it. Only use
// it on x86."* And `sigreturn__sigaction` exists in exactly two files —
// `sys_linux_386.s:499` and `sys_linux_amd64.s:482` — with no arm64
// counterpart. The arm64 kernel provides its own restorer, so
// `sigreturn_restorer()` returns 0 here.
//
// **`clone(2)`'s argument order is not the same.** arm64 is a
// `CLONE_BACKWARDS` architecture:
//
//     amd64: clone(flags, newsp, ptid, ctid, tls)   -> tls in the 5th slot
//     arm64: clone(flags, newsp, ptid, tls,  ctid)  -> tls in the 4th slot
//
// Go cannot be cited for this one, and that is worth saying out loud:
// `runtime/sys_linux_arm64.s:670-686` sets only R0 and R1 and never
// passes a TLS argument at all, because non-cgo Go/arm64 keeps `g` in
// R28 rather than in the thread pointer — `runtime/tls_arm64.s:12-18`
// short-circuits `load_g` on `iscgo`. goish does use the thread pointer
// (see `sched/tls/`), so it needs `CLONE_SETTLS` where Go does not.
//
// The slot was therefore established by experiment rather than by
// reading: a static arm64 binary cloned a thread passing a magic value
// in x3 and 0 in x4, and the child read that exact value back out of
// `TPIDR_EL0`. If this is ever revisited, re-run that probe rather than
// re-reasoning about it.

/// `clone(2)` — spawn a new OS thread sharing the parent's address
/// space. The child begins execution at `child_entry` on a fresh stack
/// pointed at by `child_stack` (which must point at the **top** of an
/// mmap'd region of at least 64 KiB). `child_entry` must be `-> !`; a
/// return from it would run off the trampoline.
///
/// Returns the child tid in the parent, and never returns in the child.
///
/// `tls != 0` ORs `CLONE_SETTLS` into the flags and plants that value in
/// the child's `TPIDR_EL0`, so the child can call `current_m()` from its
/// first instruction.
///
/// **Safety**: caller must keep `child_stack` and (if `tls != 0`) the
/// memory it points at alive for the lifetime of the child thread;
/// passing stale pointers will SIGSEGV the child.
#[allow(non_snake_case)]
#[unsafe(naked)]
pub unsafe extern "C" fn Clone(
    _flags: u64,
    _child_stack: *mut u8,
    _child_entry: extern "C" fn() -> !,
    _tls: u64,
) -> i64 {
    core::arch::naked_asm!(
        // AAPCS64 register-passed args at function entry:
        //   x0 = flags, x1 = child_stack, x2 = child_entry, x3 = tls
        //
        // Step 1: stash child_entry on the new stack, so the child can
        // recover it after x2 is reused for ptid. 16 rather than amd64's
        // 8 because AAPCS64 requires SP to stay 16-byte aligned at all
        // times — not merely at call boundaries, as SysV does.
        "sub x1, x1, #16",
        "str x2, [x1]",
        // Step 2: if tls != 0, OR CLONE_SETTLS (0x80000) into flags so
        // the kernel sets the child's TPIDR_EL0 from x3.
        "cbz x3, 3f",
        "mov x9, #0x80000",
        "orr x0, x0, x9",
        "3:",
        // Step 3: clone(2). x3 already holds tls — see the header note
        // on CLONE_BACKWARDS.
        "mov x2, #0", // ptid = 0
        "mov x4, #0", // ctid = 0
        "mov x8, #220", // SYS_clone
        "svc #0",
        // Both threads continue here. Parent: x0 > 0; child: x0 = 0 and
        // sp = child_stack-16 (the kernel set sp from x1).
        "cbz x0, 2f",
        // PARENT: x0 holds the child tid; it is already the return value.
        "ret",
        "2:",
        // CHILD: load child_entry off the stack without popping, so sp
        // stays 16-aligned when the entry function runs. TPIDR_EL0 is
        // already set by CLONE_SETTLS, so it may call current_m()
        // immediately. `br` rather than `blr`: there is nothing to
        // return to.
        "ldr x9, [sp]",
        "br x9",
    )
}

/// Address to put in `sigaction.sa_restorer`, or 0 if the target has no
/// restorer. Always 0 on arm64 — see the header note.
#[inline]
pub fn sigreturn_restorer() -> usize {
    0
}
