// asm_linux_amd64 — whole functions written in assembly.
//
// Both bodies are the verbatim blocks that used to sit in
// `syscall/mod.rs`; only this file's wrapper and the
// `sigreturn_restorer()` accessor below are new.

/// Sigreturn trampoline. The kernel jumps here when a signal
/// handler returns; this issues `rt_sigreturn(2)` which restores
/// the pre-signal context. Mandatory on amd64 (kernel has no
/// default stub since glibc dropped libgcc-style restorers).
///
/// Naked asm: just two instructions, no prologue/epilogue.
/// Mirrors Go runtime `sigreturn__sigaction`
/// (sys_linux_amd64.s:470).
#[unsafe(naked)]
#[allow(non_snake_case)]
pub unsafe extern "C" fn SigreturnTrampoline() {
    core::arch::naked_asm!(
        "movq $15, %rax",   // SYS_rt_sigreturn
        "syscall",
        // Should never return; if it does, INT3.
        "int3",
        options(att_syntax),
    )
}

/// `clone(2)` — spawn a new OS thread sharing the parent's address
/// space. The child begins execution at `child_entry` on a fresh
/// stack pointed at by `child_stack` (which must point at the **top**
/// of an mmap'd region of at least 64 KiB). `child_entry` must be
/// `extern "C"` and never return; it should call `ExitThread` when
/// done.
///
/// `tls`: Goish's per-M TLS base. In the default configuration, if
/// nonzero, the kernel sets the child's `fs` segment base to this
/// address (`CLONE_SETTLS` is OR'd into flags by the trampoline).
/// With `ffi-system-tls`, the child inherits the platform `fs` base and
/// the trampoline installs this address in `gs` using `arch_prctl`
/// before entering Rust. Pass 0 to inherit both segment bases.
///
/// Returns the child TID on the parent path. Never returns directly
/// in the child — the child immediately tail-jumps to `child_entry`.
///
/// **ABI** (matches Go runtime/sys_linux_amd64.s:561-619):
///   rdi = flags (typically `CLONE_THREAD_FLAGS`)
///   rsi = child_stack (top — kernel decrements as child uses)
///   rdx = child_entry (saved on the new stack before the syscall
///                       so we can jmp to it after the syscall
///                       clobbers our scratch regs)
///   rcx = tls (4th SysV arg; trampoline moves to r8 = clone's newtls)
///
/// **Safety**: caller must keep `child_stack` and (if `tls != 0`) the
/// memory it points at alive for the lifetime of the child thread;
/// passing stale pointers will SIGSEGV the child.
#[allow(non_snake_case)]
#[unsafe(naked)]
#[cfg(not(feature = "ffi-system-tls"))]
pub unsafe extern "C" fn Clone(
    _flags: u64,
    _child_stack: *mut u8,
    _child_entry: extern "C" fn() -> !,
    _tls: u64,
) -> i64 {
    core::arch::naked_asm!(
        // SysV register-passed args at function entry:
        //   rdi = flags, rsi = child_stack, rdx = child_entry, rcx = tls
        //
        // Step 1: stash child_entry on the new stack (so we can
        // recover it after rdx is clobbered for ptid).
        "subq $8, %rsi",
        "movq %rdx, (%rsi)",
        // Step 2: move tls (rcx, our 4th SysV arg) → r8 (clone's
        // newtls register). rcx will be clobbered by the syscall
        // anyway; we don't need it again.
        "movq %rcx, %r8",
        // Step 3: if tls != 0, OR CLONE_SETTLS (0x80000) into flags
        // so the kernel sets the child's fs base from r8.
        "testq %r8, %r8",
        "jz 3f",
        "orq $0x80000, %rdi",
        "3:",
        // Step 4: clone(2) syscall.
        "movq $56, %rax",  // SYS_clone
        "xorq %rdx, %rdx", // ptid = 0
        "xorq %r10, %r10", // ctid = 0
        "syscall",
        // Both threads continue here. Parent: rax > 0; child: rax = 0
        // and rsp = child_stack-8 (kernel set rsp from rsi).
        "testq %rax, %rax",
        "jnz 2f",
        // CHILD: load child_entry off the stack (without popping —
        // we want rsp at stack_top-8 when entry runs, so that
        // rsp+8 is 16-aligned, matching SysV's "after-CALL"
        // convention. Go's clone trampoline does this implicitly
        // by using `CALL R12` instead of JMP. fs is already set by
        // CLONE_SETTLS, so the entry function can call
        // current_m() immediately.
        "movq (%rsp), %rax",
        "jmpq *%rax",
        // PARENT: rax holds child_pid; just return.
        "2:",
        "retq",
        options(att_syntax),
    )
}

/// `clone(2)` trampoline for `ffi-system-tls` builds.
///
/// Linux's `CLONE_SETTLS` argument configures FS on x86-64, so it
/// cannot install Goish's GS-based runtime slot. This variant leaves FS
/// inherited, then performs the raw `arch_prctl(ARCH_SET_GS, tls)`
/// syscall in the child before tail-jumping to any Rust code.
#[allow(non_snake_case)]
#[unsafe(naked)]
#[cfg(feature = "ffi-system-tls")]
pub unsafe extern "C" fn Clone(
    _flags: u64,
    _child_stack: *mut u8,
    _child_entry: extern "C" fn() -> !,
    _tls: u64,
) -> i64 {
    core::arch::naked_asm!(
        "subq $16, %rsi",
        "movq %rdx, 0(%rsi)",
        "movq %rcx, 8(%rsi)",
        "andq $-524289, %rdi", // !CLONE_SETTLS (0x80000)
        "movq $56, %rax",      // SYS_clone
        "xorq %rdx, %rdx",     // ptid = 0
        "xorq %r10, %r10",     // ctid = 0
        "xorq %r8, %r8",       // newtls unused without CLONE_SETTLS
        "syscall",
        "testq %rax, %rax",
        "jnz 2f",
        "movq 8(%rsp), %rsi",
        "testq %rsi, %rsi",
        "jz 3f",
        "movq $158, %rax",    // SYS_arch_prctl
        "movq $0x1001, %rdi", // ARCH_SET_GS
        "syscall",
        "testq %rax, %rax",
        "jz 3f",
        "movq $60, %rax", // SYS_exit (this thread only)
        "movq $2, %rdi",
        "syscall",
        "ud2",
        "3:",
        "movq 0(%rsp), %rax",
        "addq $8, %rsp",
        "jmpq *%rax",
        "2:",
        "retq",
        options(att_syntax),
    )
}

/// Address to put in `sigaction.sa_restorer`, or 0 if the target has no
/// restorer.
///
/// Go: `runtime/os_linux.go:478-487` sets `_SA_RESTORER` in `sa_flags`
/// unconditionally but populates `sa_restorer` only under
/// `if GOARCH == "386" || GOARCH == "amd64"`, with the comment
/// *"Although Linux manpage says sa_restorer element is obsolete and
/// should not be used. x86_64 kernel requires it. Only use it on x86."*
/// Correspondingly `sigreturn__sigaction` is defined in
/// `sys_linux_386.s:499` and `sys_linux_amd64.s:482` and nowhere else.
#[inline]
pub fn sigreturn_restorer() -> usize {
    SigreturnTrampoline as *const () as usize
}
