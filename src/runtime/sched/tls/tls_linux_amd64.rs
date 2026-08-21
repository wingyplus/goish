// tls_linux_amd64 — thread pointer in `fs` (or `gs` with the
// `ffi-system-tls` feature), planted with arch_prctl(2).
//
// `ffi-system-tls` leaves `fs` to the platform's own TLS — so foreign
// glibc-using code keeps working on goish threads — and moves goish's
// M slot to `gs`. Every access below picks the segment by that feature;
// `base()` alone always reads `fs`, because its one caller saves the
// *platform* base for FFI workers in either mode.

use crate::syscall;

/// Value stored at thread-pointer offset 0 — goish keeps `MStorage`'s
/// `tls_self` there, so this is `current_m()`'s whole fast path.
///
/// **Must not be called before the thread's base is planted** (main:
/// `setup_main_tls`; workers: `CLONE_SETTLS`) — `fs` is uninitialized
/// at process entry and reading it would yield garbage.
#[inline]
pub unsafe fn slot0() -> usize {
    let ptr: usize;
    #[cfg(not(feature = "ffi-system-tls"))]
    core::arch::asm!(
        "mov %fs:0, {0}",
        out(reg) ptr,
        options(nostack, preserves_flags, att_syntax),
    );
    #[cfg(feature = "ffi-system-tls")]
    core::arch::asm!(
        "mov %gs:0, {0}",
        out(reg) ptr,
        options(nostack, preserves_flags, att_syntax),
    );
    ptr
}

/// Read the thread-pointer base itself. `ARCH_GET_FS` *writes* the base
/// to the given address, hence the out-param shape.
#[inline]
pub unsafe fn base() -> usize {
    let mut b: usize = 0;
    let r = syscall::ArchPrctl(syscall::ARCH_GET_FS, &mut b as *mut usize as usize);
    if r == 0 {
        b
    } else {
        0
    }
}

/// Plant the thread-pointer base. Returns 0 on success, `-errno`
/// otherwise.
#[inline]
pub unsafe fn set_base(b: usize) -> isize {
    #[cfg(not(feature = "ffi-system-tls"))]
    return syscall::ArchPrctl(syscall::ARCH_SET_FS, b);
    #[cfg(feature = "ffi-system-tls")]
    return syscall::ArchPrctl(syscall::ARCH_SET_GS, b);
}

/// `locks += 1` on the calling thread's own `MStorage`.
///
/// One instruction: the segment-relative operand does the thread-pointer
/// read and the read-modify-write together, so this cannot land on
/// another M's storage.
#[inline]
pub unsafe fn locks_inc<const OFF: usize>() {
    #[cfg(not(feature = "ffi-system-tls"))]
    core::arch::asm!(
        "lock add dword ptr fs:[{off}], 1",
        off = const OFF,
        options(nostack),
    );
    #[cfg(feature = "ffi-system-tls")]
    core::arch::asm!(
        "lock add dword ptr gs:[{off}], 1",
        off = const OFF,
        options(nostack),
    );
}

/// `locks -= 1`, returning the value from *before* the decrement.
#[inline]
pub unsafe fn locks_dec<const OFF: usize>() -> u32 {
    let prev: u32;
    #[cfg(not(feature = "ffi-system-tls"))]
    core::arch::asm!(
        "mov {p:e}, -1",
        "lock xadd dword ptr fs:[{off}], {p:e}",
        p = out(reg) prev,
        off = const OFF,
        options(nostack),
    );
    #[cfg(feature = "ffi-system-tls")]
    core::arch::asm!(
        "mov {p:e}, -1",
        "lock xadd dword ptr gs:[{off}], {p:e}",
        p = out(reg) prev,
        off = const OFF,
        options(nostack),
    );
    prev
}

/// Current frame-pointer value, for the `releasem` underflow walker.
#[inline]
pub unsafe fn frame_pointer() -> u64 {
    let fp: u64;
    core::arch::asm!("mov {}, rbp", out(reg) fp, options(nomem, nostack));
    fp
}

/// Current stack-pointer value, for `setup_main_g0`'s fallback when
/// `/proc/self/maps` cannot be parsed.
#[inline]
pub unsafe fn stack_pointer() -> usize {
    let sp: usize;
    core::arch::asm!(
        "mov {}, rsp",
        out(reg) sp,
        options(nomem, nostack, preserves_flags),
    );
    sp
}
