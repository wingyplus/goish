// sys_darwin_arm64 — the raw system interface on macOS/arm64.
//
// **There is no syscall instruction here, and that is the point.** The
// two Linux backends next door are `syscall`/`svc` plus a number table.
// This one is a set of `extern "C"` declarations against libSystem,
// because that is what Go does: `runtime/sys_darwin_arm64.s:490-566`
// defines the `libcCall` trampolines, and every Darwin primitive in the
// runtime goes through one. Apple does not commit to syscall numbers
// the way Linux does — libSystem is the ABI.
//
// `svc #0x80` *does* work on macOS/arm64 today (measured: a bare `svc`
// with `0x2000004` in x16 wrote to fd 1 and returned 14). It is still
// the wrong choice. It buys one milestone: from M3 on, every primitive
// the port needs — `pthread_create`, `pthread_cond_timedwait_relative_np`,
// `sysctlbyname`, `arc4random_buf`, `dladdr`, `getsectiondata` — is a
// libSystem function with no syscall behind it to call.
//
// ─── The return-value ABI ──────────────────────────────────────────────
//
// goish's internal contract, pinned down in `sys/mod.rs`, is Linux's:
// **a non-negative result, or a negative `-errno`**. Every one of the
// ~96 Go-shaped wrappers in `crate::syscall` and every caller of those
// is written against it. Darwin's C library does not use that shape, and
// it does not use one shape either — it uses three, so this file has
// three adapters rather than one:
//
//   * `errno_ret` — `write`/`read`/`open`/`close`/…: `-1` on failure
//     with the code in the thread's `errno`. Reached through `__error()`,
//     which returns a pointer to that thread's slot.
//   * `direct_ret` — the `pthread_*` family: the errno *is* the return
//     value, positive, and the thread's `errno` is left untouched.
//   * `ptr_ret` — `mmap`: failure is the sentinel `MAP_FAILED`
//     (`(void *) -1`), which is not distinguishable from a valid address
//     by sign alone, so it is tested for explicitly before the errno read.
//
// The errno read has to happen with **no intervening libSystem call**,
// since any of them may overwrite the slot. Each wrapper below therefore
// reads it in the same statement sequence as the call it belongs to,
// and the adapters take the already-captured return value rather than
// calling anything themselves.

/// The kernel's page size — the granule `mmap`, `mprotect` and
/// `madvise` operate on.
///
/// **16 KiB on Apple Silicon**, measured (`sysconf(_SC_PAGESIZE)`) not
/// assumed, against Linux's 4 KiB on both supported targets. This is
/// deliberately NOT `PAGE_SHIFT`: goish keeps Go's 8 KiB heap page on
/// every target (Go does the same — `runtime/malloc.go` `_PageSize` is
/// 8192 everywhere), so on Linux one kernel page is half a Go page and
/// here one Go page is *half a kernel page*. That inversion is M2's
/// whole problem; naming the two quantities apart is the prerequisite.
///
/// Go: `runtime/os_darwin.go:148-153` — `osinit` calls `getPageSize()`
/// rather than pinning a constant, precisely because Darwin's varies.
pub const PHYS_PAGE_SIZE: usize = 16384;

// ─── libSystem ─────────────────────────────────────────────────────────
//
// Declared, not defined. `libSystem.B.dylib` is linked by default for
// this target; the `#[link]` attribute states the dependency explicitly
// so a `no_std` build does not rely on `std` having pulled it in.
#[link(name = "System")]
extern "C" {
    /// Pointer to the calling thread's `errno`. Darwin's `errno` is a
    /// macro over this function, so there is no symbol to read directly.
    fn __error() -> *mut i32;

    fn write(fd: i32, buf: *const u8, n: usize) -> isize;
    fn read(fd: i32, buf: *mut u8, n: usize) -> isize;
    fn exit(code: i32) -> !;

    fn mmap(
        addr: *mut u8,
        len: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: i64,
    ) -> *mut u8;
    fn munmap(addr: *mut u8, len: usize) -> i32;
    fn mach_absolute_time() -> u64;
    fn mprotect(addr: *mut u8, len: usize, prot: i32) -> i32;
    fn madvise(addr: *mut u8, len: usize, advice: i32) -> i32;
}

/// Read the calling thread's `errno`.
///
/// **Call this immediately after the failing call and before any other
/// libSystem call**, including any that a `?`, a `Drop` or a panic path
/// might introduce.
#[inline]
pub unsafe fn errno() -> i32 {
    *__error()
}

/// Adapt a `-1`-on-failure C return into goish's negative-errno shape.
///
/// `r` must be the value the call returned and `e` the errno captured
/// straight after it — passing both in rather than reading `errno()`
/// here is what keeps the "no intervening call" rule checkable at the
/// call site instead of buried in this function.
#[inline]
pub fn errno_ret(r: isize, e: i32) -> isize {
    if r == -1 {
        -(e as isize)
    } else {
        r
    }
}

/// Adapt a `pthread_*`-family return (`0`, or a positive errno, with
/// the thread's `errno` untouched) into the negative-errno shape.
#[inline]
pub fn direct_ret(r: i32) -> isize {
    if r == 0 {
        0
    } else {
        -(r as isize)
    }
}

/// Adapt an `mmap` return into the negative-errno shape.
///
/// `MAP_FAILED` is `(void *) -1`, and a mapping address is otherwise an
/// unsigned quantity that may legitimately have its top bit set — so
/// this tests the sentinel rather than the sign.
#[inline]
pub fn ptr_ret(p: *mut u8, e: i32) -> isize {
    if p as isize == -1 {
        -(e as isize)
    } else {
        p as isize
    }
}

// ─── the primitives, in goish's ABI ────────────────────────────────────
//
// M1 needs exactly these. Everything else `crate::syscall` exposes on
// this target is an `unimplemented!()` naming its milestone — see
// `syscall/syscall_darwin.rs`.

/// `write(2)`. Returns bytes written, or `-errno`.
#[inline]
pub unsafe fn sys_write(fd: i32, p: *const u8, n: usize) -> isize {
    let r = write(fd, p, n);
    let e = errno();
    errno_ret(r, e)
}

/// `read(2)`. Returns bytes read, or `-errno`.
#[inline]
pub unsafe fn sys_read(fd: i32, p: *mut u8, n: usize) -> isize {
    let r = read(fd, p, n);
    let e = errno();
    errno_ret(r, e)
}

/// `exit(3)` — whole-process exit.
///
/// This is libSystem's `exit`, not `_exit`: it runs `atexit` handlers
/// and flushes stdio. goish writes through `write(2)` and registers no
/// handlers, so the two are equivalent here, and `exit` is what Go calls
/// (`runtime/sys_darwin.go`, `exit` → `libc_exit`).
#[inline]
pub unsafe fn sys_exit(code: i32) -> ! {
    exit(code)
}

/// `mmap(2)`. Returns the mapping address as a non-negative `isize`, or
/// `-errno`.
#[inline]
pub unsafe fn sys_mmap(
    addr: *mut u8,
    length: usize,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: i64,
) -> isize {
    let p = mmap(addr, length, prot, flags, fd, offset);
    let e = errno();
    ptr_ret(p, e)
}

/// `munmap(2)`.
#[inline]
pub unsafe fn sys_munmap(addr: *mut u8, length: usize) -> isize {
    let r = munmap(addr, length);
    let e = errno();
    errno_ret(r as isize, e)
}

/// `mprotect(2)`.
#[inline]
pub unsafe fn sys_mprotect(addr: *mut u8, length: usize, prot: i32) -> isize {
    let r = mprotect(addr, length, prot);
    let e = errno();
    errno_ret(r as isize, e)
}

/// `madvise(2)`.
///
/// **The advice values are not Linux's semantics under a different
/// number.** `MADV_DONTNEED` exists on Darwin (4) and does *not* free
/// the pages: Go uses `MADV_FREE_REUSABLE` (7) followed by
/// `MADV_FREE_REUSE` (8) for the release/re-acquire pair
/// (`runtime/mem_darwin.go:23-34`). The wrapper is neutral about which
/// is passed; M2 is where the allocator picks.
#[inline]
pub unsafe fn sys_madvise(addr: *mut u8, length: usize, advice: i32) -> isize {
    let r = madvise(addr, length, advice);
    let e = errno();
    errno_ret(r as isize, e)
}

/// `mach_absolute_time()` — the raw Mach timer, in ticks of an
/// unspecified unit.
///
/// This is what Darwin's monotonic clock is built out of: Go's
/// `nanotime1` (`runtime/sys_darwin.go:304-320`) calls it and then
/// scales by the `mach_timebase_info` numerator/denominator to get
/// nanoseconds — noting that "numer == denom == 1 is common", which is
/// the case on Apple Silicon.
///
/// goish's one caller is `runtime::cputicks`, a PRNG seed source, which
/// wants monotonic bits rather than a unit. The scaling therefore stays
/// out of this function; M3 adds it where `time.Now` needs it.
///
/// Not `-errno`-shaped and not fallible — there is no error path.
#[inline]
pub unsafe fn sys_mach_absolute_time() -> u64 {
    mach_absolute_time()
}
