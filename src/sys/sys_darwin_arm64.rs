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
// since any of them may overwrite the slot — and `__error()` is itself
// a libSystem call, so "read it always and inspect it later" would put
// a call between the primitive and its own error code on the *success*
// path. The adapters therefore take the raw return value and read errno
// themselves, inside the failure branch only. That makes the rule
// structural rather than a convention each new wrapper has to remember,
// and it keeps the success path — which is every `write` goish does —
// down to one call and one compare.

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
    fn sigaltstack(new: *const u8, old: *mut u8) -> i32;

    // M4 — threads and the TSD slot goish's thread pointer lives in.
    // `pthread_t` is an opaque pointer and `pthread_key_t` an
    // `unsigned long`; both are `usize` here.
    fn pthread_key_create(key: *mut usize, destructor: usize) -> i32;
    fn pthread_getspecific(key: usize) -> usize;
    fn pthread_setspecific(key: usize, value: usize) -> i32;
    fn pthread_self() -> usize;
    fn pthread_threadid_np(thread: usize, id: *mut u64) -> i32;
    fn pthread_get_stackaddr_np(thread: usize) -> *mut u8;
    fn pthread_get_stacksize_np(thread: usize) -> usize;

    // M3 — time, identity, entropy, CPU count.
    fn clock_gettime(clk: i32, tp: *mut u8) -> i32;
    fn nanosleep(req: *const u8, rem: *mut u8) -> i32;
    fn getpid() -> i32;
    fn kill(pid: i32, sig: i32) -> i32;
    fn getppid() -> i32;
    fn getuid() -> u32;
    fn geteuid() -> u32;
    fn getgid() -> u32;
    fn getegid() -> u32;
    fn getgroups(size: i32, list: *mut u32) -> i32;
    fn uname(buf: *mut u8) -> i32;
    fn arc4random_buf(buf: *mut u8, n: usize);
    fn sysctl(
        name: *const i32,
        namelen: u32,
        oldp: *mut u8,
        oldlenp: *mut usize,
        newp: *const u8,
        newlen: usize,
    ) -> i32;
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
/// **Safety / ordering:** call this on the value the primitive returned
/// with nothing in between — it reads the thread's `errno`, and only on
/// the failure branch, which is what keeps `__error()` (a libSystem
/// call itself) off the success path.
#[inline]
pub unsafe fn errno_ret(r: isize) -> isize {
    if r == -1 {
        -(errno() as isize)
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
/// this tests the sentinel rather than the sign. Same ordering contract
/// as `errno_ret`.
#[inline]
pub unsafe fn ptr_ret(p: *mut u8) -> isize {
    if p as isize == -1 {
        -(errno() as isize)
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
    errno_ret(r)
}

/// `read(2)`. Returns bytes read, or `-errno`.
#[inline]
pub unsafe fn sys_read(fd: i32, p: *mut u8, n: usize) -> isize {
    let r = read(fd, p, n);
    errno_ret(r)
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
    ptr_ret(p)
}

/// `munmap(2)`.
#[inline]
pub unsafe fn sys_munmap(addr: *mut u8, length: usize) -> isize {
    let r = munmap(addr, length);
    errno_ret(r as isize)
}

/// `mprotect(2)`.
#[inline]
pub unsafe fn sys_mprotect(addr: *mut u8, length: usize, prot: i32) -> isize {
    let r = mprotect(addr, length, prot);
    errno_ret(r as isize)
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
    errno_ret(r as isize)
}

/// `mach_absolute_time()` — the raw Mach timer, in ticks of an
/// unspecified unit.
///
/// This is what Darwin's monotonic clock is built out of: Go's
/// `nanotime1` (`runtime/sys_darwin.go`) calls it and then scales by
/// the `mach_timebase_info` numerator/denominator to get nanoseconds,
/// noting that "numer == denom == 1 is common". **It is not the case
/// on Apple Silicon**: measured on an M-series host, `numer = 125`,
/// `denom = 3` — a 24 MHz counter, 41.67 ns per tick. Treating ticks
/// as nanoseconds would be wrong by a factor of ~42.
///
/// goish's one caller is `runtime::cputicks`, a PRNG seed source, which
/// wants monotonic bits rather than a unit, so it takes ticks as-is.
/// Nanoseconds come from `clock_gettime(CLOCK_UPTIME_RAW)` instead —
/// the same clock with the conversion already applied (see
/// `runtime::sysmon::monotonic_ns`).
///
/// Not `-errno`-shaped and not fallible — there is no error path.
#[inline]
pub unsafe fn sys_mach_absolute_time() -> u64 {
    mach_absolute_time()
}

/// `sigaltstack(2)`. The `stack_t` pointers are untyped here because
/// the layout lives with the other generated tables in
/// `syscall/ztypes_darwin_arm64.rs` — which is BSD's `ss_sp, ss_size,
/// ss_flags`, not Linux's `ss_sp, ss_flags, ss_size`.
#[inline]
pub unsafe fn sys_sigaltstack(new: *const u8, old: *mut u8) -> isize {
    let r = sigaltstack(new, old);
    errno_ret(r as isize)
}

// ─── pthreads (M4) ─────────────────────────────────────────────────────
//
// All `direct_ret`-shaped except the three that cannot fail
// (`pthread_self`, `pthread_getspecific`, the two `_np` stack queries),
// which return their value as-is.

/// `pthread_key_create(&key, NULL)`. Returns the key, or `-errno`.
#[inline]
pub unsafe fn sys_pthread_key_create() -> Result<usize, isize> {
    let mut k: usize = 0;
    let r = pthread_key_create(&mut k, 0);
    if r == 0 { Ok(k) } else { Err(direct_ret(r)) }
}

/// `pthread_getspecific(key)` — the slow, library-mediated read of the
/// slot `sched::tls` otherwise reads directly. Used once, to prove the
/// two agree.
#[inline]
pub unsafe fn sys_pthread_getspecific(key: usize) -> usize {
    pthread_getspecific(key)
}

/// `pthread_setspecific(key, value)`.
#[inline]
pub unsafe fn sys_pthread_setspecific(key: usize, value: usize) -> isize {
    direct_ret(pthread_setspecific(key, value))
}

/// `pthread_self()` — the calling thread's `pthread_t`. This, not a
/// kernel thread id, is what `pthread_kill` targets (Go's `signalM`).
#[inline]
pub unsafe fn sys_pthread_self() -> usize {
    pthread_self()
}

/// `pthread_threadid_np(pthread_self(), &id)` — the system-wide 64-bit
/// thread id `ps -M` and Instruments show. The closest Darwin has to
/// Linux's `gettid`.
#[inline]
pub unsafe fn sys_thread_id() -> u64 {
    let mut id: u64 = 0;
    let _ = pthread_threadid_np(0, &mut id);
    id
}

/// `(stack top, stack size)` of `thread`, as libpthread records them.
/// The top is the *highest* address — Darwin's `stackaddr` is where the
/// stack starts growing down from, not the base of the mapping.
#[inline]
pub unsafe fn sys_pthread_stack(thread: usize) -> (usize, usize) {
    (
        pthread_get_stackaddr_np(thread) as usize,
        pthread_get_stacksize_np(thread),
    )
}

// ─── time, identity, entropy, CPU count (M3) ───────────────────────────

/// `clock_gettime(2)`. The clock ids are Darwin's, not Linux's — see
/// `syscall/zerrors_darwin_arm64.rs` — and one of them does not mean
/// what its name suggests there: Darwin's `CLOCK_MONOTONIC` counts time
/// asleep. `CLOCK_UPTIME_RAW` is the one that matches Go's `nanotime`.
#[inline]
pub unsafe fn sys_clock_gettime(clk: i32, tp: *mut u8) -> isize {
    let r = clock_gettime(clk, tp);
    errno_ret(r as isize)
}

/// `nanosleep(2)`.
#[inline]
pub unsafe fn sys_nanosleep(req: *const u8, rem: *mut u8) -> isize {
    let r = nanosleep(req, rem);
    errno_ret(r as isize)
}

/// `getpid`/`getppid` — cannot fail.
#[inline]
pub unsafe fn sys_getpid() -> i32 { getpid() }
#[inline]
pub unsafe fn sys_getppid() -> i32 { getppid() }

/// `getuid`/`geteuid`/`getgid`/`getegid` — cannot fail. `uid_t` and
/// `gid_t` are unsigned 32-bit here as on Linux.
#[inline]
pub unsafe fn sys_getuid() -> u32 { getuid() }
#[inline]
pub unsafe fn sys_geteuid() -> u32 { geteuid() }
#[inline]
pub unsafe fn sys_getgid() -> u32 { getgid() }
#[inline]
pub unsafe fn sys_getegid() -> u32 { getegid() }

/// `getgroups(2)`. Count on success, `-errno` on failure.
#[inline]
pub unsafe fn sys_getgroups(size: i32, list: *mut u32) -> isize {
    let r = getgroups(size, list);
    errno_ret(r as isize)
}

/// `uname(3)` — a libc function here, not a syscall; it fills the
/// struct from `sysctl`. The layout is `ztypes_darwin_arm64.rs`'s
/// `Utsname`: five 256-byte fields, no `domainname`.
#[inline]
pub unsafe fn sys_uname(buf: *mut u8) -> isize {
    let r = uname(buf);
    errno_ret(r as isize)
}

/// `arc4random_buf(3)` — fill `buf` from the kernel CSPRNG. Cannot fail
/// and does not block. Go's darwin `readRandom` is this call
/// (`runtime/os_darwin.go`).
#[inline]
pub unsafe fn sys_arc4random_buf(buf: *mut u8, n: usize) {
    arc4random_buf(buf, n)
}

/// `sysctl(3)` on a two-level MIB, reading a `u32`. Returns `None` on
/// failure. Go's darwin `getCPUCount`/`getPageSize` use exactly this
/// shape (`runtime/os_darwin.go`).
#[inline]
pub unsafe fn sys_sysctl_u32(mib0: i32, mib1: i32) -> Option<u32> {
    let mib = [mib0, mib1];
    let mut out: u32 = 0;
    let mut n = core::mem::size_of::<u32>();
    let r = sysctl(mib.as_ptr(), 2, &mut out as *mut u32 as *mut u8, &mut n, core::ptr::null(), 0);
    if r == 0 { Some(out) } else { None }
}

/// `kill(2)`.
#[inline]
pub unsafe fn sys_kill(pid: i32, sig: i32) -> isize {
    let r = kill(pid, sig);
    errno_ret(r as isize)
}
