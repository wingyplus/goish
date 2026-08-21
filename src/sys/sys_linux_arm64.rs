// sys_linux_arm64 — raw Linux/arm64 system calls.
//
// Calling convention (AAPCS64 / Linux arm64 `svc #0`):
//   x8 = syscall number
//   x0, x1, x2, x3, x4, x5 = args 1..6
//   x0 = return (negative = -errno)
//   x1-x7 and x9-x30 are preserved by the kernel; NZCV is not.
//
// Go's `runtime/sys_linux_arm64.s:95-102` (`runtime·write1`) is the
// canonical shape: args into R0..R2, `MOVD $SYS_write, R8`, `SVC`,
// result out of R0. Its `#define SYS_write 64` / `SYS_exit 93` /
// `SYS_mmap 222` (lines 19, 21, 26) are the same asm-generic numbers
// the arm64 tables in `syscall/` carry.
//
// Two differences from amd64 that matter here, and only here:
//
//   * The number goes in **x8**, not the return register. amd64 puts it
//     in rax and gets the result back in rax (`inlateout`); arm64 keeps
//     them separate, so `n` is a plain `in("x8")`.
//   * **No clobbers.** amd64's `syscall` instruction destroys rcx and
//     r11 as a side effect of the instruction itself; `svc` has no such
//     behaviour and the kernel restores everything but x0. What `svc`
//     does not promise is the condition flags, so `preserves_flags` is
//     deliberately absent below — it appears on every amd64 stub and on
//     none of these.
//
// See `sys/mod.rs` for why the instruction lives behind a facade.

use core::arch::asm;

/// 0-argument syscall — used by `fork(2)` and `getpid(2)`.
#[inline]
pub unsafe fn syscall0(n: usize) -> isize {
    let ret: isize;
    asm!(
        "svc #0",
        in("x8") n,
        lateout("x0") ret,
        options(nostack),
    );
    ret
}

/// 1-argument syscall.
#[inline]
pub unsafe fn syscall1(n: usize, a1: usize) -> isize {
    let ret: isize;
    asm!(
        "svc #0",
        in("x8") n,
        inlateout("x0") a1 => ret,
        options(nostack),
    );
    ret
}

/// 2-argument syscall — used by `clock_gettime` / `nanosleep`.
#[inline]
pub unsafe fn syscall2(n: usize, a1: usize, a2: usize) -> isize {
    let ret: isize;
    asm!(
        "svc #0",
        in("x8") n,
        inlateout("x0") a1 => ret,
        in("x1") a2,
        options(nostack),
    );
    ret
}

/// 3-argument syscall (write, read, open).
#[inline]
pub unsafe fn syscall3(n: usize, a1: usize, a2: usize, a3: usize) -> isize {
    let ret: isize;
    asm!(
        "svc #0",
        in("x8") n,
        inlateout("x0") a1 => ret,
        in("x1") a2,
        in("x2") a3,
        options(nostack),
    );
    ret
}

/// 4-argument syscall (newfstatat).
#[inline]
pub unsafe fn syscall4(n: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> isize {
    let ret: isize;
    asm!(
        "svc #0",
        in("x8") n,
        inlateout("x0") a1 => ret,
        in("x1") a2,
        in("x2") a3,
        in("x3") a4,
        options(nostack),
    );
    ret
}

/// 6-argument syscall (mmap).
#[inline]
pub unsafe fn syscall6(
    n: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
) -> isize {
    let ret: isize;
    asm!(
        "svc #0",
        in("x8") n,
        inlateout("x0") a1 => ret,
        in("x1") a2,
        in("x2") a3,
        in("x3") a4,
        in("x4") a5,
        in("x5") a6,
        options(nostack),
    );
    ret
}
