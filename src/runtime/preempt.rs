// runtime::preempt — asynchronous preemption via SIGURG (M18b-α).
//
// Phase C — full injection. The SIGURG handler installs a kernel-
// level pushCall on the user G's `ucontext`, redirecting it through
// `goish_async_preempt` (asm trampoline). The trampoline saves all
// GPRs, enabled SIMD registers, FP controls, and flags, then calls
// `goish_async_preempt2` (Rust),
// which yields the G via the cooperative scheduler. When the G is
// later resumed, control returns into the trampoline epilogue, which
// restores everything and `jmp`s back to the user's original PC —
// without writing to the user's red zone (`[SP_user-128, SP_user)`),
// because the trampoline's first instruction shifts SP below it.
//
// ─── Pipeline (Go's runtime/preempt.go + signal_unix.go +
//     signal_amd64.go) ─────────────────────────────────────────────
//
//   1. Sender (sysmon, or in tests a goroutine) issues
//      `tgkill`/`kill` with SIGURG.
//   2. Kernel saves the full register set into `ucontext_t` and
//      enters `goish_preempt_sigtramp` (SA_SIGINFO).
//   3. Handler runs the canPreemptM-equivalent predicates
//      (`isAsyncSafePoint` from preempt.go:363):
//        a. m.locks == 0
//        b. PC ∉ trampoline range
//        c. M.curg = Some(g)
//        d. g.status = Running
//        e. SP has the CPU-dependent `async_preempt_stack()` headroom.
//   4. If all pass: write user PC to `[SP_user-144]`, below the red
//      zone, and set ucontext.RIP to the trampoline and RSP to SP-8.
//      The handler runs on the per-M alternate signal stack.
//   5. Sigreturn → trampoline → `goish_async_preempt2` (yields) → on
//      resume, restore the G's own saved state and jump to its saved PC.
//
// ─── Why a separate handler from `os::signal::goish_sigtramp`? ─
//
// `os::signal::Notify` uses a single-arg handler that bumps a
// counter and wakes sysmon. It is intentionally minimal — async-
// signal-safe with no lock-free reads of M state. The preempt path
// needs three-arg `SA_SIGINFO` so it can inspect and modify the
// saved register set in `ucontext`. Keeping the two paths separate
// avoids overloading the established os::signal handler shape.

use core::arch::naked_asm;
use core::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};

use crate::runtime::sched::{current_g, current_m, current_m_locks, GStatus, Gosched};
use crate::syscall;

// ─── ucontext_t layout (Linux x86_64) ──────────────────────────────
//
// Mirrors `/usr/include/x86_64-linux-gnu/sys/ucontext.h` and the
// kernel's `arch/x86/include/uapi/asm/sigcontext.h`. We define only
// the prefix we read/write; the trailing sigset/fpregs storage is
// represented as opaque padding.
//
// Cross-checked against Go's `runtime/defs_linux_amd64.go`:
//   - `type stackt`  ↔ `StackT` here
//   - `type sigcontext` (inline `gregs[23]` etc.) ↔ `McontextT`
//   - `type ucontext` ↔ `UcontextT`
//
// Field order is load-bearing — the kernel writes specific offsets.

#[repr(C)]
pub struct StackT {
    pub ss_sp: *mut u8,
    pub ss_flags: i32,
    _pad0: i32,
    pub ss_size: usize,
}

/// `mcontext_t` — saved register state pushed by the kernel on
/// signal entry. `gregs` is a 23-element array of `u64`; indices are
/// the `REG_*` constants below.
#[repr(C)]
pub struct McontextT {
    pub gregs: [u64; 23],
    pub fpregs: usize,
    pub _reserved: [u64; 8],
}

/// `ucontext_t` — the third argument to a SA_SIGINFO handler.
#[repr(C)]
pub struct UcontextT {
    pub uc_flags: u64,
    pub uc_link: *mut UcontextT,
    pub uc_stack: StackT,
    pub uc_mcontext: McontextT,
    // uc_sigmask + fpregs storage follow but we don't read or write
    // them; the kernel allocated the full struct, only the offsets
    // we touch matter.
}

// Linux x86_64 register indices in `gregs[]`. Matches
// arch/x86/include/uapi/asm/sigcontext.h enums.
pub const REG_R8: usize = 0;
pub const REG_R9: usize = 1;
pub const REG_R10: usize = 2;
pub const REG_R11: usize = 3;
pub const REG_R12: usize = 4;
pub const REG_R13: usize = 5;
pub const REG_R14: usize = 6;
pub const REG_R15: usize = 7;
pub const REG_RDI: usize = 8;
pub const REG_RSI: usize = 9;
pub const REG_RBP: usize = 10;
pub const REG_RBX: usize = 11;
pub const REG_RDX: usize = 12;
pub const REG_RAX: usize = 13;
pub const REG_RCX: usize = 14;
pub const REG_RSP: usize = 15;
pub const REG_RIP: usize = 16;
pub const REG_EFL: usize = 17;

// go: none — Goish can interrupt arbitrary Rust AVX code, without Go's
// compiler safe-point metadata. Preserve the vector state the OS enables.
// x87, SSE, AVX, AVX-512 opmasks/ZMM: AMX and unrelated state such as PKRU
// require a separate runtime contract and are intentionally not claimed here.
const SIMD_XFEATURES: u64 = 0xe7;
static FP_STATE_MASK: AtomicU64 = AtomicU64::new(0); // zero selects FXSAVE
static FP_STATE_SIZE: AtomicUsize = AtomicUsize::new(512);
static FP_STATE_READY: AtomicU8 = AtomicU8::new(0);

/// Minimum headroom for the FXSAVE fallback. Includes the red zone/resume
/// slots (160), GPR area (128), alignment slack (63), return PC (8), and
/// 4 KiB for the Rust scheduler call chain. XSAVE adds its detected size.
/// Use `async_preempt_stack()` for the actual budget on this host.
pub const ASYNC_PREEMPT_STACK: usize = 160 + 128 + 63 + 8 + 4096 + 512;

// go: none — standard-format XSAVE size for the vector state we preserve.
fn fp_state_layout() -> (u64, usize) {
    use core::arch::x86_64::{__cpuid, __cpuid_count, _xgetbv};
    let features = __cpuid(1).ecx;
    if __cpuid(0).eax < 0x0d || features & (3 << 26) != (3 << 26) {
        return (0, 512);
    }
    let supported = __cpuid_count(0x0d, 0);
    let supported = u64::from(supported.eax) | (u64::from(supported.edx) << 32);
    // SAFETY: XSAVE and OSXSAVE were checked above. Only read OS policy;
    // never change XCR0. The selected mask stays immutable after install.
    let mask = unsafe { _xgetbv(0) } & supported & SIMD_XFEATURES;
    if mask & 3 != 3 {
        return (0, 512);
    }
    let mut size = 576; // legacy area plus the 64-byte XSAVE header
    for component in [2, 5, 6, 7] {
        if mask & (1 << component) != 0 {
            let leaf = __cpuid_count(0x0d, component);
            let end = usize::try_from(leaf.ebx).unwrap() + usize::try_from(leaf.eax).unwrap();
            size = size.max(end);
        }
    }
    return (mask, size);
}

// go: none — publish once before installing the signal handler. Reinstalling
// the handler must not change the layout beneath a suspended trampoline.
fn initialize_fp_state() {
    if FP_STATE_READY
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        let (mask, size) = fp_state_layout();
        FP_STATE_SIZE.store(size, Ordering::Relaxed);
        FP_STATE_MASK.store(mask, Ordering::Relaxed);
        FP_STATE_READY.store(2, Ordering::Release);
    } else {
        while FP_STATE_READY.load(Ordering::Acquire) != 2 {
            core::hint::spin_loop();
        }
    }
}

// go: none — CPU-dependent headroom, also exposed for boundary diagnostics.
/// Stack space required before injecting an asynchronous preemption.
#[inline]
pub fn async_preempt_stack() -> usize {
    return ASYNC_PREEMPT_STACK + FP_STATE_SIZE.load(Ordering::Relaxed) - 512;
}

// `goish_async_preempt_end` — a symbol the trampoline's naked_asm
// block emits immediately after the final `jmp`. Used to compute
// the trampoline's *exact* PC range for `is_in_trampoline`. Without
// this, a fixed-size bound would catch unrelated text under LTO
// (functions sharing the same `.text` section).
extern "C" {
    fn goish_async_preempt_end();
    fn goish_swap_context_end();
    // M17b-ε β.2/β.3: end-markers for the new asm primitives. The
    // SIGURG handler refuses injection when PC falls inside `gogo`'s
    // load-and-JMP or `mcall_asm`'s save-and-switch — same rationale
    // as `swap_context`: half-switched RSP would crash the trampoline.
    fn goish_gogo_end();
    fn goish_mcall_end();
}

// ─── Diagnostic counters ───────────────────────────────────────────
//
// All `Relaxed` — the test only needs an eventual snapshot, and the
// signal handler runs on the same thread that produced the writes,
// so happens-before is implicit on x86 anyway.

static PREEMPT_INVOCATIONS: AtomicU64 = AtomicU64::new(0);
static PREEMPT_INJECTIONS: AtomicU64 = AtomicU64::new(0);
static SKIP_LOCKS: AtomicU64 = AtomicU64::new(0);
static SKIP_TRAMPOLINE: AtomicU64 = AtomicU64::new(0);
static SKIP_PARKING: AtomicU64 = AtomicU64::new(0);
static SKIP_NO_CURG: AtomicU64 = AtomicU64::new(0);
static SKIP_NOT_RUNNING: AtomicU64 = AtomicU64::new(0);
static SKIP_SP_RANGE: AtomicU64 = AtomicU64::new(0);

/// Ring buffer of the last 32 user PCs at which the handler injected
/// the async-preempt trampoline. Filled mod 32 by the handler; read
/// from the panic handler / diagnostics. Diagnostic only — used to
/// correlate panic-time state with the user-code site that was
/// preempted.
const INJECT_RING_LEN: usize = 32;
static INJECT_RING: [AtomicU64; INJECT_RING_LEN] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; INJECT_RING_LEN]
};

/// Read a snapshot of the last `count` injection PCs (most-recent
/// first, up to `min(count, 32)`). Out-param style for no-alloc use.
/// Returns the number written.
pub fn snapshot_injection_pcs(out: &mut [u64]) -> usize {
    let count = out.len().min(INJECT_RING_LEN);
    let total = PREEMPT_INJECTIONS.load(Ordering::Relaxed) as usize;
    let mut written = 0;
    let mut i = 0;
    while i < count && i < total {
        // Most recent first: index = (total - 1 - i) mod RING_LEN.
        let slot = (total + INJECT_RING_LEN - 1 - i) % INJECT_RING_LEN;
        out[i] = INJECT_RING[slot].load(Ordering::Relaxed);
        written += 1;
        i += 1;
    }
    written
}

/// Total handler invocations since process start.
pub fn invocations() -> u64 {
    PREEMPT_INVOCATIONS.load(Ordering::Relaxed)
}

/// Times the handler injected an asyncPreempt call. Each injection
/// causes the targeted G to yield via `goish_async_preempt2`.
pub fn injections() -> u64 {
    PREEMPT_INJECTIONS.load(Ordering::Relaxed)
}

/// Per-skip-reason counts. Order:
/// (locks, trampoline, parking, no_curg, not_running, sp_range).
pub fn skip_breakdown() -> (u64, u64, u64, u64, u64, u64) {
    (
        SKIP_LOCKS.load(Ordering::Relaxed),
        SKIP_TRAMPOLINE.load(Ordering::Relaxed),
        SKIP_PARKING.load(Ordering::Relaxed),
        SKIP_NO_CURG.load(Ordering::Relaxed),
        SKIP_NOT_RUNNING.load(Ordering::Relaxed),
        SKIP_SP_RANGE.load(Ordering::Relaxed),
    )
}

// ─── is_in_trampoline ──────────────────────────────────────────────

#[inline]
fn is_in_trampoline(pc: u64) -> bool {
    let start = goish_async_preempt as *const () as usize as u64;
    let end = goish_async_preempt_end as *const () as usize as u64;
    pc >= start && pc < end
}

/// True when the saved RIP falls inside `swap_context`'s asm. We
/// must skip injection in this window — between the final
/// `mov rsp, [rsi+0x00]` and `ret`, RSP points at the *target* G's
/// stack but the user PC hasn't yet been popped, so an injection
/// would resume the trampoline on a half-switched context and
/// crash on a stale return address. Mirrors the role of Go's
/// PCDATA_UnsafePoint marking on `runtime/asm_amd64.s:gogo`.
#[inline]
fn is_in_swap_context(pc: u64) -> bool {
    let start = crate::runtime::sched::swap_context as *const () as usize as u64;
    let end = goish_swap_context_end as *const () as usize as u64;
    pc >= start && pc < end
}

/// True when the saved RIP falls inside `gogo`'s asm — the
/// JMP-into-G primitive. Same half-switched-stack risk as
/// `is_in_swap_context`: between `mov rsp, [rdi+0x00]` and the
/// final indirect JMP through gobuf.pc, RSP belongs to the resuming
/// G but PC has not yet transferred. SIGURG injection here would
/// crash the trampoline on the target G's stack with an undefined
/// resume PC.
#[inline]
fn is_in_gogo(pc: u64) -> bool {
    let start = crate::runtime::sched::gogo as *const () as usize as u64;
    let end = goish_gogo_end as *const () as usize as u64;
    pc >= start && pc < end
}

/// True when the saved RIP falls inside `mcall_asm`'s save-and-switch
/// asm. Mirrors `is_in_swap_context`: between the partial save of
/// caller's PC/SP into `*from` and the `call rdx` that re-enters
/// scheduler code on g0, the M's stack pointer is mid-transition.
#[inline]
fn is_in_mcall_asm(pc: u64) -> bool {
    // mcall_asm is `pub(crate)` so we can't take its address through
    // a `pub use`; reach into the module directly.
    let start = crate::runtime::sched::mcall_asm as *const () as usize as u64;
    let end = goish_mcall_end as *const () as usize as u64;
    pc >= start && pc < end
}

// ─── async_preempt2: the Rust half ─────────────────────────────────
//
// Called after the interrupted G's registers are saved on its own stack.
// Gosched switches to the scheduler stack and makes this G runnable. Its
// suspended trampoline and FP image travel with it if it resumes on another M.

#[no_mangle]
#[inline(never)]
#[link_section = "goish_rt_text"]
extern "C" fn goish_async_preempt2() {
    // **Yield via Gosched, not gopark+commit.**
    //
    // Earlier versions used `gopark(preempt_park_commit, _)` where
    // the commit fn called `goready` to immediately re-make the G
    // runnable. That mirrored *the shape* of Go's `goschedImpl(gp,
    // true)` but added a transient `Waiting` state and a same-M
    // `dispatch_one_g→commit→goready` round-trip — neither of
    // which Go's path has. Go's `mcall(gopreempt_m)` switches to
    // g0, sets status `Running→Runnable`, dropg, globrunqput,
    // schedule(): no Waiting, no commit fn.
    //
    // `Gosched()` is goish's equivalent: status flip
    // `Running→Runnable`, enqueue on local runq tail (`next=false`,
    // FIFO — matches Go's `globrunqput` semantics), swap to the
    // scheduler stack, on resume status flip back to `Running`.
    // No commit fn, no Waiting transition, no `goready` call. The
    // m.locks bookkeeping inside Gosched stays self-contained on
    // the originating M (the swap_context happens before any
    // migration window opens), so the migration imbalance the
    // earlier `acquirem`/`releasem` workaround addressed cannot
    // occur on this path.
    let _ = current_g();
    Gosched();
}

// ─── goish_async_preempt: the asm trampoline ───────────────────────
//
// Entry: %rsp = SP_user - 8, %rip = trampoline. Kernel-set, by
// `goish_preempt_sigtramp`'s ucontext writes.
//
// Stack layout, top-to-bottom (each row 8 bytes unless noted):
//
//     [SP_user]                                ← %rsp at jmp back
//     [SP_user-8]    user's original byte      ← %rsp at entry
//     [SP_user-128]  ↘ user red-zone untouched (no writes here)
//     [SP_user-136]  user_rax snapshot         ← rsp after sub $128
//     [SP_user-144]  resume_pc snapshot        ← written by SIGURG handler
//     [SP_user-152]  saved BP                  ← rsp after pushq rbp
//     [SP_user-160]  saved FLAGS               ← rsp after pushfq
//     ...            128-byte GPR save area, then CPU-sized FP area
//     [save_top..]    XSAVE (64-aligned), or 512-byte FXSAVE fallback
//     [save_top - 8] return PC for async_preempt2 call
//
// The resume PC and all register state belong to the G's stack frame.
// Per-M scratch is insufficient: while this G yields, the same M may
// preempt another G, and this G may resume on a different M.
// The epilogue uses RBP to find the fixed GPR area above the CPU-sized
// FP area, then restores the original stack pointer and resume PC.
//
// Calling convention: `extern "C"` so `call` semantics match SysV.
// Naked: no Rust prologue/epilogue.

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn goish_async_preempt() {
    naked_asm!(
        // ── Prologue ──
        //
        // **EFLAGS preservation discipline (entry side, M28-fix-2).**
        // The kernel preserves the user's EFLAGS across signal
        // delivery — `rt_sigreturn` restores `ucontext.gregs[REG_EFL]`
        // to RFLAGS before transferring control to our modified
        // `ucontext.RIP`. So at trampoline entry, RFLAGS *is* the
        // user's pre-SIGURG flags.
        //
        // Until we `pushfq` to capture them, NO flag-clobbering
        // instruction may execute — otherwise pushfq saves garbage
        // and the matching epilogue `popfq` restores garbage,
        // breaking the user's resume-PC conditional branch (e.g.
        // a `jne` after a `cmp` from before SIGURG hit). Use `lea`
        // for RSP arithmetic in this window; `push`/`mov` are
        // flag-preserving by ISA spec.
        //
        // Mirrors the epilogue's "`popfq` last among flag-touchers"
        // discipline: the prologue's `pushfq` is FIRST among
        // flag-touchers.

        // Step 1: shift SP below the user's red zone (`[SP_user-128,
        // SP_user)`). Anything we push from here on lives strictly
        // below the red zone, leaving leaf-fn locals untouched.
        // `lea` (not `sub`) preserves user's EFLAGS for pushfq below.
        "lea rsp, [rsp - 128]",                      // rsp = SP_user-136

        // Step 2 (M18b-δ.3): advance RSP past the resume-PC slot —
        // the handler has *already* written the resume PC to
        // [SP_user-144] (see goish_preempt_sigtramp). With the
        // SIGURG handler running on the per-M alt signal stack
        // (SA_ONSTACK + sigaltstack), the kernel never touches the
        // user G's stack during signal delivery, so the handler's
        // write is the only writer for this slot until the epilogue
        // reads it. `lea` (not `sub`) preserves EFLAGS.
        "lea rsp, [rsp - 8]",                        // rsp = SP_user-144 (slot written by handler)

        // Step 3: standard frame pointer. `push` and `mov` are
        // both ISA-spec flag-preserving — EFLAGS still = user's.
        "push rbp",                                  // [SP_user-152] = user BP
        "mov rbp, rsp",                              // rbp = SP_user-152 — frame anchor

        // Step 4: save user's EFLAGS. `pushfq` MUST be the first
        // flag-touching instruction in the trampoline; everything
        // above is `lea`/`push`/`mov` (all flag-preserving).
        "pushfq",                                    // [SP_user-160] = user FLAGS

        // Step 5: fixed GPR area at rbp-136. Save every GPR before
        // using scratch registers to allocate the variable FP area.
        "sub rsp, 128",

        // Step 6: save 14 GPRs (rax,rcx,rdx,rbx,rsi,rdi,r8-r15) at
        // offsets 0..104 (RBP and RSP are not in the save area —
        // RBP is on stack via pushq, RSP is implicit).
        "mov [rsp + 0],   rax",
        "mov [rsp + 8],   rcx",
        "mov [rsp + 16],  rdx",
        "mov [rsp + 24],  rbx",
        "mov [rsp + 32],  rsi",
        "mov [rsp + 40],  rdi",
        "mov [rsp + 48],  r8",
        "mov [rsp + 56],  r9",
        "mov [rsp + 64],  r10",
        "mov [rsp + 72],  r11",
        "mov [rsp + 80],  r12",
        "mov [rsp + 88],  r13",
        "mov [rsp + 96],  r14",
        "mov [rsp + 104], r15",

        // Step 7: variable-size FP area, owned by this suspended G's
        // frame (never per-M scratch). Both paths use 64-byte alignment,
        // which also satisfies the SysV call alignment below.
        "sub rsp, qword ptr [rip + {state_size}]",
        "and rsp, -64",
        "mov rax, qword ptr [rip + {state_mask}]",
        "test rax, rax",
        "jz 2f",
        // XSAVE does not initialize all header/reserved bits. This is a
        // fresh stack image, so clear its header with INTEGER stores:
        // vector instructions here could destroy the state being saved.
        "mov qword ptr [rsp + 512], 0",
        "mov qword ptr [rsp + 520], 0",
        "mov qword ptr [rsp + 528], 0",
        "mov qword ptr [rsp + 536], 0",
        "mov qword ptr [rsp + 544], 0",
        "mov qword ptr [rsp + 552], 0",
        "mov qword ptr [rsp + 560], 0",
        "mov qword ptr [rsp + 568], 0",
        "mov rdx, rax",
        "shr rdx, 32",
        "xsave64 [rsp]",
        // Avoid AVX -> legacy SSE transition costs in scheduler code.
        // Only do this after saving, and only if OS-enabled AVX is present.
        "test eax, 4",
        "jz 3f",
        "vzeroupper",
        "jmp 3f",
        "2:",
        "fxsave64 [rsp]",
        "3:",

        // ── Body ──
        // Gosched manages m.locks around the scheduler transition.
        // The trampoline's PC range is filtered by `is_in_trampoline(PC)` in the
        // handler, covering the prologue/epilogue windows where
        // m.locks could be 0.
        "call {async_preempt2}",

        // ── Epilogue ──
        // Restore FP/vector state before tearing down this G's frame.
        // The masks/layout are immutable even if the G migrated to another M.
        "mov rax, qword ptr [rip + {state_mask}]",
        "test rax, rax",
        "jz 4f",
        "mov rdx, rax",
        "shr rdx, 32",
        "xrstor64 [rsp]",
        "jmp 5f",
        "4:",
        "fxrstor64 [rsp]",
        "5:",
        // No vector instructions or Rust calls after restoring state.
        "lea rsp, [rbp - 136]",
        "mov rax, [rsp + 0]",
        "mov [rbp + 16], rax",

        // Restore the other GPRs (rax stays as scratch — restored
        // below from the [rbp+16] snapshot, BEFORE popfq).
        "mov rcx, [rsp + 8]",
        "mov rdx, [rsp + 16]",
        "mov rbx, [rsp + 24]",
        "mov rsi, [rsp + 32]",
        "mov rdi, [rsp + 40]",
        "mov r8,  [rsp + 48]",
        "mov r9,  [rsp + 56]",
        "mov r10, [rsp + 64]",
        "mov r11, [rsp + 72]",
        "mov r12, [rsp + 80]",
        "mov r13, [rsp + 88]",
        "mov r14, [rsp + 96]",
        "mov r15, [rsp + 104]",

        // ── EFLAGS preservation discipline (M28-fix, hardened) ──
        //
        // After `popfq` restores user EFLAGS, the user's resume PC
        // may be a conditional branch reading ZF/CF/SF set by a
        // `cmp`/`test` immediately before the SIGURG injection
        // (concretely: `current_m`'s alignment check
        // `cmp $0x0, %rax; jne <panic>` — saved EFLAGS reflects
        // that cmp; ANY flag-clobbering instruction between popfq
        // and the resume jmp causes JNE to branch on stale flags
        // and panic spuriously).
        //
        // Mirroring Go's `asyncPreempt` epilogue shape (which ends
        // `…; POPFQ; POPQ BP; RET` — three architecturally
        // flag-preserving instructions): we restore rax BEFORE
        // popfq (where flag-clobbering is harmless because the
        // saved-flag slot is about to overwrite EFLAGS), then
        // commit the post-popfq window to ONLY:
        //
        //     popfq            ; restores user FLAGS
        //     pop rbp          ; ISA-spec: flag-preserving
        //     lea rsp, [...]   ; SIB arithmetic, flag-preserving
        //     jmp qword [mem]  ; memory-operand JMP, flag-preserving
        //
        // No `add`/`sub`/`xor`/`test`/`cmp`/`inc`/`dec`/`and`/`or`
        // may appear between popfq and the resume jmp. If you need
        // RSP arithmetic, use `lea`.

        // Restore user's rax from the [rbp+16] snapshot — placed
        // BEFORE popfq deliberately so that even though `mov` is
        // flag-preserving, we shrink the post-popfq window to
        // strictly the smallest set of necessary instructions.
        "mov rax, [rbp + 16]",                       // rax = user_rax

        // Reset rsp to the popfq slot via rbp anchor (lea = flag-safe,
        // but flags don't matter yet — popfq is next).
        "lea rsp, [rbp - 8]",                        // rsp = SP_user-160 (popfq slot)

        // ─── BEGIN flag-sensitive window ──────────────────────────
        "popfq",                                     // rsp = SP_user-152, FLAGS = user's
        "pop rbp",                                   // rsp = SP_user-144, rbp = user's (flag-safe)
        "lea rsp, [rsp + 144]",                      // rsp = SP_user (flag-safe — lea)
        "jmp qword ptr [rsp - 144]",                 // jump to resume_pc (flag-safe — mem-op JMP)
        // ─── END flag-sensitive window ────────────────────────────

        // Emit a global end-of-trampoline label inline so
        // `is_in_trampoline` can compute the exact PC range. `int3`
        // ensures any errant fall-through traps loudly.
        ".globl goish_async_preempt_end",
        "goish_async_preempt_end:",
        "int3",

        async_preempt2 = sym goish_async_preempt2,
        state_size = sym FP_STATE_SIZE,
        state_mask = sym FP_STATE_MASK,
    )
}

// ─── Handler ───────────────────────────────────────────────────────
//
// SA_SIGINFO calling convention: `(int sig, siginfo_t *info, void *ctx)`.
// `ctx` is `ucontext_t *`. Runs on the per-M alternate signal stack,
// leaving the interrupted G's red zone and register-save frame untouched.
//
// **Allowed operations** (all async-signal-safe):
//   - lock-free atomic loads/stores (counters, m.locks)
//   - reading the M's struct via `data_unchecked()` (Theorem 1
//     applies: at L=0 no concurrent write is in flight)
//   - reading G.status, G.stack metadata
//   - writing the resume PC below the interrupted G's red zone
//   - writing to ucontext.gregs (kernel-allocated, single-thread)
//
// **Forbidden** (would deadlock or violate AS-safety):
//   - SpinLock acquisition (`current_m().lock()`, etc.)
//   - heap allocation
//   - any `gopark` / `swap_context` (handler is *not* the trampoline)

extern "C" fn goish_preempt_sigtramp(_sig: i32, _info: *const u8, ctx: *mut UcontextT) {
    PREEMPT_INVOCATIONS.fetch_add(1, Ordering::Relaxed);

    // 1. m.locks == 0
    if current_m_locks() != 0 {
        SKIP_LOCKS.fetch_add(1, Ordering::Relaxed);
        return;
    }

    let pc = unsafe { (*ctx).uc_mcontext.gregs[REG_RIP] };

    // 2. PC ∉ trampoline range AND PC ∉ {swap_context, gogo,
    // mcall_asm} range. All of these are runtime asm windows where
    // m.locks == 0 but injection would corrupt scheduler state by
    // hijacking a half-switched RSP.
    if is_in_trampoline(pc) || is_in_swap_context(pc) || is_in_gogo(pc) || is_in_mcall_asm(pc) {
        SKIP_TRAMPOLINE.fetch_add(1, Ordering::Relaxed);
        return;
    }

    // 2b. PC ∈ goish runtime text section. Mirrors Go's
    // `name.HasPrefix("runtime.")` filter (preempt.go:420). Runtime
    // functions have brief windows where `m.locks == 0` but the
    // scheduler / lock primitive / wake-protocol state is
    // half-mutated; injecting there yields the G with that state
    // visible to other Ms, causing corruption (SEGV) or stuck
    // wakeups (hang). The cooperative path catches these Gs at the
    // next `raw_unlock` safe point — no forward-progress loss.
    if crate::runtime::rt_section::is_in_runtime(pc) {
        crate::runtime::rt_section::SKIP_RUNTIME_PC.fetch_add(1, Ordering::Relaxed);
        return;
    }

    // 3. M has a current G — lock-free read justified by Theorem 1
    // (m.locks == 0 ⟹ no concurrent write to current_g).
    let m = unsafe { current_m().data_unchecked() };
    let g_ptr = match m.curg {
        Some(p) => p,
        None => {
            SKIP_NO_CURG.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    // 4. The G is not mid-park. `gopark` sets `M.waitunlockf` (and
    // `M.waitlock`) under `m.locks > 0`, then drops the lock and
    // calls `releasem` *before* `swap_context` (Go-style discipline,
    // proc.go:419). The window between `releasem` and the
    // `swap_context` asm is precisely when `m.locks == 0` while the
    // M is committed to a park — injecting a preempt here would
    // overwrite the parker's commit fn and either deadlock the chan
    // it was supposed to release or corrupt scheduler state.
    //
    // `waitunlockf` is `Option<ParkCommit>` (8-byte fn pointer with
    // niche), naturally aligned, written only under `m.locks > 0`.
    // At `m.locks == 0` (already gated above) the read is stable.
    if m.waitunlockf.is_some() {
        SKIP_PARKING.fetch_add(1, Ordering::Relaxed);
        return;
    }

    // 5. G.status == Running
    let g_ref = unsafe { g_ptr.as_ref() };
    if g_ref.status != GStatus::Running {
        SKIP_NOT_RUNNING.fetch_add(1, Ordering::Relaxed);
        return;
    }

    // 6. Reserve the detected FP image, alignment, and scheduler call headroom.
    let sp = unsafe { (*ctx).uc_mcontext.gregs[REG_RSP] } as usize;
    let stack_lo = g_ref.stack.base();
    let stack_hi = g_ref.stack.top();
    if sp < stack_lo || sp - stack_lo < async_preempt_stack() || sp >= stack_hi {
        SKIP_SP_RANGE.fetch_add(1, Ordering::Relaxed);
        return;
    }

    // ── Inject ──
    //
    // **M18b-δ.3 — handler-direct G-stack write (SA_ONSTACK variant).**
    // Stash the resume PC directly onto G's stack at `[sp - 144]`,
    // the same slot the trampoline epilogue's final `jmp qword ptr
    // [rsp - 144]` reads. This eliminates the per-M
    // `MStorage.preempt_resume_pc` intermediate (and the trampoline's
    // earlier `push qword fs:[…]` snapshot of it).
    //
    // **Why this is safe**: the SIGURG handler is installed with
    // `SA_ONSTACK`, and every M registers a per-thread alt signal
    // stack via `sigaltstack(2)` at startup
    // (`runtime::sched::m::install_signal_stack`, called from
    // `setup_main_tls` and `mstart`). The kernel therefore allocates
    // the rt_sigframe and the handler frame on the alt stack — the
    // user G's stack is *not touched at all* by the kernel during
    // signal delivery. Writing to `[sp - 144]` from the handler is
    // guaranteed to land on the user G's own stack, in territory
    // that no other writer (kernel sigframe, other Gs, other Ms)
    // can reach.
    //
    // The 128-byte SysV red zone is preserved: -144 is below the
    // red zone at `[sp - 128, sp)`.
    //
    // RSP is shifted down by 8 so the trampoline's prologue offsets
    // (`sub rsp, 128; sub rsp, 8; push rbp; …`) land at the same
    // physical addresses they did under the δ.2 layout.
    unsafe {
        ((sp - 144) as *mut u64).write(pc);
        (*ctx).uc_mcontext.gregs[REG_RSP] = (sp - 8) as u64;
        (*ctx).uc_mcontext.gregs[REG_RIP] = goish_async_preempt as *const () as u64;
    }

    // Clear the cooperative-preempt flag (M18b-β/γ): we're about to
    // honor the request asynchronously, so the next safe-point check
    // doesn't need to fire again. Sysmon will re-set it on its next
    // tick if the G is still hogging the M.
    g_ref.preempt.store(false, Ordering::Release);

    // Record the user PC just before injection into the ring buffer
    // (mod RING_LEN) for post-mortem correlation with panic state.
    let prev = PREEMPT_INJECTIONS.fetch_add(1, Ordering::Relaxed);
    let slot = (prev as usize) % INJECT_RING_LEN;
    INJECT_RING[slot].store(pc as u64, Ordering::Relaxed);
}

// ─── Install ───────────────────────────────────────────────────────

/// Install the SIGURG preempt handler. Idempotent. Called from
/// `__goish_rt0` after sysmon has started.
///
/// Uses SA_SIGINFO so the kernel passes `(sig, info, ctx)` and we
/// can reach `ucontext`. SA_RESTORER + the existing
/// `SigreturnTrampoline` complete the kernel's mandated sigreturn
/// path.
pub fn install() {
    initialize_fp_state();
    // `SA_ONSTACK`: every M has registered a per-thread alt signal
    // stack via `sigaltstack(2)` at startup
    // (`runtime::sched::m::install_signal_stack`). With this flag,
    // the kernel allocates the rt_sigframe and runs the handler on
    // that alt stack rather than on the user G's stack. M18b-δ.3's
    // handler-direct write to `[user_rsp - 144]` depends on this:
    // without SA_ONSTACK, the kernel's sigframe could overlap the
    // slot (FPU xstate size is host-CPU dependent).
    let sa = syscall::Sigaction {
        sa_handler: goish_preempt_sigtramp as *const () as usize,
        sa_flags: syscall::SA_SIGINFO
            | syscall::SA_RESTORER
            | syscall::SA_RESTART
            | syscall::SA_ONSTACK,
        sa_restorer: syscall::SigreturnTrampoline as *const () as usize,
        sa_mask: 0,
    };
    unsafe {
        let r = syscall::RtSigaction(syscall::SIGURG, &sa as *const _, core::ptr::null_mut());
        if r != 0 {
            const MSG: &[u8] = b"goish: preempt: rt_sigaction(SIGURG) failed\n";
            syscall::Write(syscall::STDERR, MSG.as_ptr(), MSG.len());
            syscall::Exit(2);
        }
    }
}
