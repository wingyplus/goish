// runtime::sched::gobuf — saved register set + the asm context switch.
//
// Layout of `Gobuf` (offsets are load-bearing — referenced by the
// `naked_asm!` block below):
//
//   off  field   purpose
//    0   rsp     stack pointer; the PC to resume at lives at `[rsp]`
//    8   rbp     base / frame pointer
//   16   rbx     callee-saved
//   24   r12     callee-saved
//   32   r13     callee-saved
//   40   r14     callee-saved
//   48   r15     callee-saved
//
// We don't store rip/rax/rdi/rsi/rdx/rcx/r8/r9/r10/r11 because they
// are caller-saved in SysV — Rust calling code cannot rely on them
// being preserved across a function call (which `swap_context` looks
// like, from the caller's POV), so we don't need to round-trip them.
//
// Bit-for-bit mirror of Go's gobuf for the registers that survive
// `gogo`'s "longjmp" semantics. We don't carry `g`, `ctxt`, or `lr`:
//
//   - `g` — Go uses R14 to address the current goroutine via TLS;
//     M16b will introduce a parallel mechanism, but M16a doesn't
//     need it.
//   - `ctxt` — closure context pointer, only meaningful when
//     resuming a closure (relevant once goroutines spawn closures).
//   - `lr` — link register, irrelevant on amd64.


// The assembly bodies live one file per target — see
// `sched/gobuf_asm_amd64.rs` / `sched/gobuf_asm_arm64.rs`.
#[cfg(target_arch = "x86_64")]
pub use super::gobuf_asm_amd64::{swap_context, gogo, mcall_asm};
#[cfg(target_arch = "aarch64")]
pub use super::gobuf_asm_arm64::{swap_context, gogo, mcall_asm};


/// Saved register file for a suspended G. Layout matches Go's
/// `runtime.gobuf` semantically. Offsets 0x00..0x38 are the legacy
/// `swap_context` save/restore region (rsp/rbp/rbx/r12-r15) and are
/// PINNED for asm compat — `swap_context` uses literal offsets in
/// `naked_asm!`. M17b-ε β.1 adds `pc` at offset 0x38 for `gogo`'s
/// JMP-based resume; legacy `swap_context` does not touch it (it
/// resumes via RET-pops-PC-from-stack).
#[repr(C)]
#[derive(Default)]
pub struct Gobuf {
    /// Saved stack pointer. Loaded into `rsp` on resume.
    pub rsp: u64,
    /// Saved base pointer.
    pub rbp: u64,
    /// Saved callee-saved registers.
    pub rbx: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    /// Saved program counter. Used by `gogo` (β.2): loaded via `JMP`
    /// to resume without a RET. `swap_context` does NOT write/read
    /// this field — its RET resumes by popping PC from `[rsp]`.
    pub pc: u64,
}

/// Field offsets — verified at compile time. Asm uses these as
/// literal constants.
pub const GOBUF_RSP: usize = 0x00;
pub const GOBUF_RBP: usize = 0x08;
pub const GOBUF_RBX: usize = 0x10;
pub const GOBUF_R12: usize = 0x18;
pub const GOBUF_R13: usize = 0x20;
pub const GOBUF_R14: usize = 0x28;
pub const GOBUF_R15: usize = 0x30;
pub const GOBUF_PC: usize = 0x38;

const _: () = {
    assert!(core::mem::offset_of!(Gobuf, rsp) == GOBUF_RSP);
    assert!(core::mem::offset_of!(Gobuf, rbp) == GOBUF_RBP);
    assert!(core::mem::offset_of!(Gobuf, rbx) == GOBUF_RBX);
    assert!(core::mem::offset_of!(Gobuf, r12) == GOBUF_R12);
    assert!(core::mem::offset_of!(Gobuf, r13) == GOBUF_R13);
    assert!(core::mem::offset_of!(Gobuf, r14) == GOBUF_R14);
    assert!(core::mem::offset_of!(Gobuf, r15) == GOBUF_R15);
    assert!(core::mem::offset_of!(Gobuf, pc) == GOBUF_PC);
};

impl Gobuf {
    pub const fn new() -> Self {
        Gobuf {
            rsp: 0,
            rbp: 0,
            rbx: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            pc: 0,
        }
    }
}

/// Set up `gobuf` so that the first `swap_context(_, gobuf)` enters
/// `entry` running on the stack `[stack_base, stack_top)`.
///
/// `stack_top` must be 16-byte aligned (mmap-page-aligned suffices).
/// The function reserves the topmost 16 bytes of the stack as the
/// initial frame:
///
///     stack_top - 8    `goexit_trampoline` address (executed if
///                       `entry` ever returns; abort for now)
///     stack_top - 16   `entry` address (popped by the first RET in
///                       `swap_context`)
///
/// After construction, `gobuf.rsp` points at `stack_top - 16`. When
/// `swap_context` loads this gobuf and executes RET, it pops `entry`
/// and jumps. The stack alignment (rsp % 16 == 8 at function entry)
/// matches the SysV convention.
///
/// Safety: caller must have allocated a writable stack
/// `[stack_base, stack_top)` of at least 32 bytes; `entry` must be
/// a valid `extern "C" fn() -> !` address.
pub unsafe fn make_context(gobuf: &mut Gobuf, stack_top: usize, entry: extern "C" fn() -> !) {
    debug_assert!(stack_top % 16 == 0, "stack_top not 16-byte aligned");

    let sp = stack_top - 16;
    // Topmost slot — return address if `entry` ever falls through.
    *((stack_top - 8) as *mut usize) = goexit_trampoline as *const () as usize;
    // Below — first PC popped by the initial RET.
    *(sp as *mut usize) = entry as usize;

    *gobuf = Gobuf::new();
    gobuf.rsp = sp as u64;
}

/// Set up `gobuf` so that a future `gogo(&gobuf)` enters `entry` on
/// `[stack_base, stack_top)`.
///
/// Mirrors Go's `gostartcall` (runtime/stack.go) — used by `newproc`
/// to lay out a fresh G's first execution context.
///
/// Layout (different from `make_context`'s swap_context layout):
///
///     stack_top - 8    `goexit_trampoline` address — popped by
///                       `entry`'s RET if it ever falls through.
///     gobuf.rsp        = stack_top - 8     (one slot above trampoline)
///     gobuf.pc         = entry             (loaded into RIP via JMP)
///
/// The first `gogo(&gobuf)` JMPs to `entry` with `rsp = stack_top - 8`.
/// At entry, `rsp % 16 == 8` (because the trampoline slot is 8 bytes
/// below the 16-aligned `stack_top`), matching the SysV convention as
/// if `entry` had been CALLed.
///
/// Safety: caller must have allocated a writable stack
/// `[stack_base, stack_top)` of at least 16 bytes; `entry` must be a
/// valid `extern "C" fn() -> !` address; `stack_top` must be 16-byte
/// aligned.
pub unsafe fn make_context_gogo(gobuf: &mut Gobuf, stack_top: usize, entry: extern "C" fn() -> !) {
    debug_assert!(stack_top % 16 == 0, "stack_top not 16-byte aligned");
    let sp = stack_top - 8;
    // Trampoline catches the case where `entry` returns.
    *(sp as *mut usize) = goexit_trampoline as *const () as usize;
    *gobuf = Gobuf::new();
    gobuf.rsp = sp as u64;
    gobuf.pc = entry as u64;
}

/// Fallback PC if a coroutine entry function returns. M16a doesn't
/// have a scheduler to dispatch to, so this aborts the process. M16b
/// replaces it with `runtime.goexit1` semantics — return the G to
/// the scheduler.
extern "C" fn goexit_trampoline() -> ! {
    const MSG: &[u8] = b"goish: sched: goroutine returned without scheduler\n";
    crate::syscall::Write(crate::syscall::STDERR, MSG.as_ptr(), MSG.len());
    crate::syscall::Exit(2);
}
