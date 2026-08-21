// tls_darwin_arm64 — the thread pointer on macOS/arm64.
//
// Split in two, and the split is the whole content of this file: the
// two *register reads* port unchanged from Linux/arm64 because they are
// AAPCS64 facts, and the five *thread-pointer* operations do not port
// at all, because Darwin's thread pointer is not goish's to plant.
//
// ─── Why `set_base` cannot simply `msr tpidr_el0` ─────────────────────
//
// On Linux/arm64, `TPIDR_EL0` is writable at EL0 and belongs to
// whoever gets there first, so goish plants each M's `MStorage` address
// in it and `current_m()` is one load. On Darwin the register is
// libSystem's: it holds the pthread TSD base, and every `pthread_*`
// call, the ObjC runtime and the malloc zones all read through it.
// Overwriting it would not give goish a thread pointer, it would
// unmake the thread.
//
// Go's answer is to *share* the region rather than replace it:
// `runtime/tls_arm64.h:22-25` selects `MRS TPIDRRO_EL0` on Darwin, and
// `runtime/tls_arm64.s:21-26` masks the low three bits ("Darwin
// sometimes returns unaligned pointers") before indexing by an offset
// derived from a `pthread_key`. So the read-only register still
// supplies the base; read-only applies to the *slot allocation*, not to
// the read. goish will do the same — a `pthread_key_create` at M4, the
// key's slot holding the `MStorage` pointer, and the three-instruction
// `MRS` fast path as a later step once `pthread_getspecific` is proven.
//
// That is M4, and M1 does not reach it: the staged `__goish_rt0` on
// this target never calls `setup_main_tls`, so `is_tls_ready()` is
// false for the life of the process and `acquirem`/`releasem`
// short-circuit before touching anything here.
//
// Go: `runtime/tls_arm64.h:22-25`, `runtime/tls_arm64.s:21-26`,
// `runtime/os_darwin.go:233-258` (`pthread_create`).

/// Abort naming the milestone that supplies the real implementation.
#[cold]
#[inline(never)]
fn m4(what: &[u8]) -> ! {
    let msg = b"goish: the darwin/arm64 thread pointer is not implemented yet (M4): ";
    crate::syscall::Write(crate::syscall::STDERR, msg.as_ptr(), msg.len());
    crate::syscall::Write(crate::syscall::STDERR, what.as_ptr(), what.len());
    crate::syscall::Write(crate::syscall::STDERR, b"\n".as_ptr(), 1);
    crate::syscall::Exit(2)
}

/// Value at thread-pointer offset 0 — `current_m()`'s fast path. M4.
///
/// Reached only if something calls `current_m()` before M4 lands. On
/// Linux that would be a null dereference; here it names itself.
#[inline]
pub unsafe fn slot0() -> usize {
    m4(b"slot0 / current_m")
}

/// Read the thread-pointer base. M4.
#[inline]
pub unsafe fn base() -> usize {
    m4(b"base")
}

/// Plant the thread-pointer base. M4 — see the header for why this is
/// not one `msr` the way it is on Linux/arm64.
#[inline]
#[allow(unused_variables)]
pub unsafe fn set_base(b: usize) -> isize {
    m4(b"set_base")
}

/// `locks += 1` on the calling thread's own `MStorage`. M4.
#[inline]
pub unsafe fn locks_inc<const OFF: usize>() {
    m4(b"locks_inc / acquirem")
}

/// `locks -= 1`, returning the pre-decrement value. M4.
#[inline]
pub unsafe fn locks_dec<const OFF: usize>() -> u32 {
    m4(b"locks_dec / releasem")
}

// ─── the two that do port ──────────────────────────────────────────────
//
// Neither touches the thread pointer; both are AAPCS64 register reads,
// identical to the Linux/arm64 file. Apple's ABI additionally *mandates*
// the frame pointer and the `[x29]`/`[x29+8]` frame record, where on
// Linux it is a `-C force-frame-pointers=yes` build flag — so the
// backtrace walkers above this are on firmer ground here than anywhere
// else in the port.

/// Current frame-pointer value, for the `releasem` underflow walker.
#[inline]
pub unsafe fn frame_pointer() -> u64 {
    let fp: u64;
    core::arch::asm!("mov {}, x29", out(reg) fp, options(nomem, nostack));
    fp
}

/// Current stack-pointer value.
///
/// Its Linux caller is `setup_main_g0`'s fallback for when
/// `/proc/self/maps` cannot be parsed. There is no `/proc` here at all,
/// so on this target the fallback is the only path — until M4, where
/// `pthread_get_stackaddr_np` replaces the maps parse outright and makes
/// `setup_main_g0` simpler than its Linux counterpart rather than harder.
#[inline]
pub unsafe fn stack_pointer() -> usize {
    let sp: usize;
    core::arch::asm!(
        "mov {}, sp",
        out(reg) sp,
        options(nomem, nostack, preserves_flags),
    );
    sp
}
