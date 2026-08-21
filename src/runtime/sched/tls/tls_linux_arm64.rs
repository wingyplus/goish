// tls_linux_arm64 — thread pointer in `TPIDR_EL0`.
//
// Go: `runtime/tls_arm64.h:9-13` — `#ifdef GOOS_linux` selects
// `MRS TPIDR_EL0, R0`; `runtime/tls_arm64.s:21-26` reads it and applies
// the `AND $0xfffffffffffffff8` alignment fixup only under
// `#ifdef TLS_darwin`, so on Linux the raw value is used as-is.
//
// Unlike amd64, no syscall is involved in either direction: TPIDR_EL0 is
// readable *and writable* at EL0, so `set_base` is one `msr` where
// amd64 needs `arch_prctl(ARCH_SET_FS)`. arm64 Linux has no
// `arch_prctl` at all, which is why the operation is a facade rather
// than a syscall-number difference.

use core::sync::atomic::{AtomicU32, Ordering};

/// Read `TPIDR_EL0`.
#[inline]
unsafe fn tpidr() -> usize {
    let tp: usize;
    core::arch::asm!(
        "mrs {0}, tpidr_el0",
        out(reg) tp,
        options(nomem, nostack, preserves_flags),
    );
    tp
}

/// Value stored at thread-pointer offset 0 — goish keeps `MStorage`'s
/// `tls_self` there, so this is `current_m()`'s whole fast path.
///
/// **Must not be called before the thread's base is planted** (main:
/// `setup_main_tls`; workers: `CLONE_SETTLS`) — `TPIDR_EL0` is zero at
/// process entry and this would dereference a null pointer.
#[inline]
pub unsafe fn slot0() -> usize {
    *(tpidr() as *const usize)
}

/// Read the thread-pointer base itself.
#[inline]
pub unsafe fn base() -> usize {
    tpidr()
}

/// Plant the thread-pointer base. Always succeeds — `msr` to
/// `TPIDR_EL0` is unprivileged — so the `isize` result exists only to
/// match the amd64 signature, where the same operation is a syscall
/// that can fail.
#[inline]
pub unsafe fn set_base(b: usize) -> isize {
    core::arch::asm!(
        "msr tpidr_el0, {0}",
        in(reg) b,
        options(nomem, nostack, preserves_flags),
    );
    0
}

/// `locks += 1` on the calling thread's own `MStorage`.
///
/// **This is where amd64's single-instruction guarantee is lost, and it
/// cannot be recovered.** `lock add dword ptr fs:[off], 1` fuses the
/// thread-pointer read with the read-modify-write; arm64 has no
/// addressing mode that indexes off TPIDR_EL0, so the base read and the
/// RMW are separate. If the thread is migrated between them, the RMW
/// lands on the *previous* M's `locks`.
///
/// What makes that survivable today: goish only migrates a G between Ms
/// at a `gopark`/`schedule` boundary, and `acquirem` exists precisely to
/// forbid parking, so no yield point falls inside this window. A signal
/// arriving mid-window returns to the same thread and the same base.
/// The invariant is therefore "no migration without a park" rather than
/// "the RMW is indivisible" — weaker, and worth re-checking whenever
/// preemption changes (M8) or under the weak-memory audit (M12).
///
/// `SeqCst` matches x86's `lock` prefix, which is a full barrier. It is
/// almost certainly stronger than this counter needs; leaving it strict
/// keeps the port a port, and M12 is where it gets measured rather than
/// guessed.
#[inline]
pub unsafe fn locks_inc<const OFF: usize>() {
    let p = (tpidr() + OFF) as *mut u32;
    AtomicU32::from_ptr(p).fetch_add(1, Ordering::SeqCst);
}

/// `locks -= 1`, returning the value from *before* the decrement.
/// Same two-step caveat as `locks_inc`.
#[inline]
pub unsafe fn locks_dec<const OFF: usize>() -> u32 {
    let p = (tpidr() + OFF) as *mut u32;
    AtomicU32::from_ptr(p).fetch_sub(1, Ordering::SeqCst)
}

/// Current frame-pointer value, for the `releasem` underflow walker.
///
/// AAPCS64 makes `x29` the frame pointer and mandates the frame record
/// `[x29] = caller x29`, `[x29+8] = return address` — the same shape as
/// x86's `[rbp]`/`[rbp+8]`, so the walker above this ports unchanged.
#[inline]
pub unsafe fn frame_pointer() -> u64 {
    let fp: u64;
    core::arch::asm!("mov {}, x29", out(reg) fp, options(nomem, nostack));
    fp
}

/// Current stack-pointer value, for `setup_main_g0`'s fallback when
/// `/proc/self/maps` cannot be parsed.
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
