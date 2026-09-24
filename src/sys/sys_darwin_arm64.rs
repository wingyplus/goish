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

// ─── M7: threads, yield, and the futex stand-in ────────────────────────

#[link(name = "System")]
extern "C" {
    fn pthread_attr_init(attr: *mut PthreadAttr) -> i32;
    fn pthread_attr_setstack(attr: *mut PthreadAttr, addr: *mut u8, size: usize) -> i32;
    fn pthread_attr_setdetachstate(attr: *mut PthreadAttr, state: i32) -> i32;
    fn pthread_attr_destroy(attr: *mut PthreadAttr) -> i32;
    fn pthread_create(
        thread: *mut usize,
        attr: *const PthreadAttr,
        start: extern "C" fn(*mut u8) -> *mut u8,
        arg: *mut u8,
    ) -> i32;
    fn pthread_exit(value: *mut u8) -> !;
    fn sched_yield() -> i32;

    // The kernel's address-keyed wait queue — Darwin's futex. Private
    // to libSystem but load-bearing for Apple's own libc++
    // (`std::atomic::wait`) and for Rust's std on macOS, so it is not
    // going anywhere. `__ulock_wait2` (macOS 11, the Rust target's
    // deployment floor) takes the timeout in nanoseconds.
    fn __ulock_wait2(op: u32, addr: *mut u8, value: u64, timeout_ns: u64, value2: u64) -> i32;
    fn __ulock_wake(op: u32, addr: *mut u8, wake_value: u64) -> i32;
}

/// `pthread_attr_t` — `__PTHREAD_ATTR_SIZE__` (56) plus the `__sig`
/// word on arm64 (`<sys/_pthread/_pthread_types.h>`).
#[repr(C, align(8))]
struct PthreadAttr([u8; 64]);

const PTHREAD_CREATE_DETACHED: i32 = 2;

/// Start a detached pthread running `start(arg)` on the caller-owned
/// stack `[base, base + size)`. Returns the `pthread_t`, or `-errno`.
///
/// The stack is the caller's rather than libpthread's for the same
/// reason `clone(2)` takes one on Linux: the M's `g0` adopts exactly
/// this region, and its bounds have to be the thread's real ones.
/// `pthread_attr_setstack` wants both ends page aligned, which a fresh
/// `mmap` of a page multiple is. Go's darwin `newosproc` lets
/// libpthread allocate instead (`runtime/os_darwin.go`) because Go's
/// g0 bounds are read back afterwards; goish sets them before the
/// thread exists.
pub unsafe fn sys_pthread_spawn(
    base: *mut u8,
    size: usize,
    start: extern "C" fn(*mut u8) -> *mut u8,
    arg: *mut u8,
) -> isize {
    let mut attr = PthreadAttr([0; 64]);
    let r = pthread_attr_init(&mut attr);
    if r != 0 {
        return -(r as isize);
    }
    let mut r = pthread_attr_setstack(&mut attr, base, size);
    if r == 0 {
        r = pthread_attr_setdetachstate(&mut attr, PTHREAD_CREATE_DETACHED);
    }
    let mut t: usize = 0;
    if r == 0 {
        r = pthread_create(&mut t, &attr, start, arg);
    }
    pthread_attr_destroy(&mut attr);
    if r == 0 { t as isize } else { -(r as isize) }
}

/// `pthread_exit(NULL)` — end the calling thread only.
pub unsafe fn sys_pthread_exit() -> ! {
    pthread_exit(core::ptr::null_mut())
}

/// `sched_yield(2)`.
#[inline]
pub unsafe fn sys_sched_yield() -> isize {
    errno_ret(sched_yield() as isize)
}

/// `UL_COMPARE_AND_WAIT` — process-private, 32-bit compare.
const UL_COMPARE_AND_WAIT: u32 = 1;
/// Return `-errno` rather than setting `errno` (`ULF_NO_ERRNO`).
const ULF_NO_ERRNO: u32 = 0x0100_0000;
/// Wake every waiter rather than one (`ULF_WAKE_ALL`).
const ULF_WAKE_ALL: u32 = 0x0000_0100;

/// Block while `*addr == expected`, for at most `timeout_ns` (0 means
/// forever). 0 on wake, or `-errno`: `-ETIMEDOUT`, `-EINTR`, and a
/// value mismatch returns at once. Same contract as
/// `futex(FUTEX_WAIT_PRIVATE)`, which is why this backs `Futex` here.
#[inline]
pub unsafe fn sys_ulock_wait(addr: *const u32, expected: u32, timeout_ns: u64) -> isize {
    let r = __ulock_wait2(
        UL_COMPARE_AND_WAIT | ULF_NO_ERRNO,
        addr as *mut u8,
        expected as u64,
        timeout_ns,
        0,
    );
    if r < 0 { r as isize } else { 0 }
}

/// Wake one waiter on `addr`, or all of them. Waking an address nobody
/// waits on is `-ENOENT` from the kernel, and not an error to a futex
/// caller, so it reads as 0 woken.
#[inline]
pub unsafe fn sys_ulock_wake(addr: *const u32, all: bool) -> isize {
    let op = UL_COMPARE_AND_WAIT | ULF_NO_ERRNO | if all { ULF_WAKE_ALL } else { 0 };
    let r = __ulock_wake(op, addr as *mut u8, 0);
    if r < 0 { 0 } else { 1 }
}

// ─── M2: the file surface ──────────────────────────────────────────────
//
// Plain libSystem calls; each wrapper turns `-1`+`errno` into `-errno`.
// `open`, `openat` and `fcntl` are C-variadic, and on Apple arm64 a
// variadic argument travels on the stack rather than in a register —
// declaring them with a fixed third parameter would compile, link, and
// pass garbage for the mode. They are declared variadic here for that
// reason alone.

#[link(name = "System")]
extern "C" {
    fn open(path: *const u8, flags: i32, ...) -> i32;
    fn openat(dirfd: i32, path: *const u8, flags: i32, ...) -> i32;
    fn close(fd: i32) -> i32;
    fn fsync(fd: i32) -> i32;
    fn fstat(fd: i32, st: *mut u8) -> i32;
    fn stat(path: *const u8, st: *mut u8) -> i32;
    fn lstat(path: *const u8, st: *mut u8) -> i32;
    fn fstatat(dirfd: i32, path: *const u8, st: *mut u8, flags: i32) -> i32;
    fn statfs(path: *const u8, buf: *mut u8) -> i32;
    fn lseek(fd: i32, off: i64, whence: i32) -> i64;
    fn pread(fd: i32, buf: *mut u8, n: usize, off: i64) -> isize;
    fn pwrite(fd: i32, buf: *const u8, n: usize, off: i64) -> isize;
    fn ftruncate(fd: i32, len: i64) -> i32;
    fn truncate(path: *const u8, len: i64) -> i32;
    fn flock(fd: i32, op: i32) -> i32;
    fn mkdir(path: *const u8, mode: u16) -> i32;
    fn mkdirat(dirfd: i32, path: *const u8, mode: u16) -> i32;
    fn mkfifo(path: *const u8, mode: u16) -> i32;
    fn mknod(path: *const u8, mode: u16, dev: i32) -> i32;
    fn umask(mask: u16) -> u16;
    fn unlink(path: *const u8) -> i32;
    fn unlinkat(dirfd: i32, path: *const u8, flags: i32) -> i32;
    fn rmdir(path: *const u8) -> i32;
    fn getcwd(buf: *mut u8, size: usize) -> *mut u8;
    fn chdir(path: *const u8) -> i32;
    fn fchdir(fd: i32) -> i32;
    fn chmod(path: *const u8, mode: u16) -> i32;
    fn fchmod(fd: i32, mode: u16) -> i32;
    fn fchmodat(dirfd: i32, path: *const u8, mode: u16, flags: i32) -> i32;
    fn chown(path: *const u8, uid: u32, gid: u32) -> i32;
    fn lchown(path: *const u8, uid: u32, gid: u32) -> i32;
    fn fchown(fd: i32, uid: u32, gid: u32) -> i32;
    fn fchownat(dirfd: i32, path: *const u8, uid: u32, gid: u32, flags: i32) -> i32;
    fn symlink(target: *const u8, link: *const u8) -> i32;
    fn symlinkat(target: *const u8, dirfd: i32, link: *const u8) -> i32;
    fn readlink(path: *const u8, buf: *mut u8, n: usize) -> isize;
    fn readlinkat(dirfd: i32, path: *const u8, buf: *mut u8, n: usize) -> isize;
    fn utimensat(dirfd: i32, path: *const u8, times: *const u8, flags: i32) -> i32;
    fn rename(from: *const u8, to: *const u8) -> i32;
    fn renameat(fromfd: i32, from: *const u8, tofd: i32, to: *const u8) -> i32;
    fn link(from: *const u8, to: *const u8) -> i32;
    fn linkat(fromfd: i32, from: *const u8, tofd: i32, to: *const u8, flags: i32) -> i32;
    fn dup(fd: i32) -> i32;
    fn dup2(fd: i32, to: i32) -> i32;
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;

    // The one private call in this block: the kernel's own directory
    // reader, which libc's `readdir` sits on. Go avoids it for App
    // Store reasons and simulates it with `fdopendir`/`readdir_r` in
    // O(n²) (`syscall/syscall_darwin.go:256-316`); goish has no such
    // constraint.
    fn __getdirentries64(fd: i32, buf: *mut u8, n: usize, basep: *mut i64) -> isize;
}

macro_rules! libc_ret {
    ($($name:ident = $c:ident($($arg:ident: $ty:ty),*) -> $r:ty;)*) => {$(
        #[inline]
        pub unsafe fn $name($($arg: $ty),*) -> isize {
            errno_ret($c($($arg),*) as isize)
        }
    )*};
}

libc_ret! {
    sys_close = close(fd: i32) -> i32;
    sys_fsync = fsync(fd: i32) -> i32;
    sys_fstat = fstat(fd: i32, st: *mut u8) -> i32;
    sys_stat = stat(path: *const u8, st: *mut u8) -> i32;
    sys_lstat = lstat(path: *const u8, st: *mut u8) -> i32;
    sys_fstatat = fstatat(dirfd: i32, path: *const u8, st: *mut u8, flags: i32) -> i32;
    sys_statfs = statfs(path: *const u8, buf: *mut u8) -> i32;
    sys_lseek = lseek(fd: i32, off: i64, whence: i32) -> i64;
    sys_pread = pread(fd: i32, buf: *mut u8, n: usize, off: i64) -> isize;
    sys_pwrite = pwrite(fd: i32, buf: *const u8, n: usize, off: i64) -> isize;
    sys_ftruncate = ftruncate(fd: i32, len: i64) -> i32;
    sys_truncate = truncate(path: *const u8, len: i64) -> i32;
    sys_flock = flock(fd: i32, op: i32) -> i32;
    sys_mkdir = mkdir(path: *const u8, mode: u16) -> i32;
    sys_mkdirat = mkdirat(dirfd: i32, path: *const u8, mode: u16) -> i32;
    sys_mkfifo = mkfifo(path: *const u8, mode: u16) -> i32;
    sys_mknod = mknod(path: *const u8, mode: u16, dev: i32) -> i32;
    sys_unlink = unlink(path: *const u8) -> i32;
    sys_unlinkat = unlinkat(dirfd: i32, path: *const u8, flags: i32) -> i32;
    sys_rmdir = rmdir(path: *const u8) -> i32;
    sys_chdir = chdir(path: *const u8) -> i32;
    sys_fchdir = fchdir(fd: i32) -> i32;
    sys_chmod = chmod(path: *const u8, mode: u16) -> i32;
    sys_fchmod = fchmod(fd: i32, mode: u16) -> i32;
    sys_fchmodat = fchmodat(dirfd: i32, path: *const u8, mode: u16, flags: i32) -> i32;
    sys_chown = chown(path: *const u8, uid: u32, gid: u32) -> i32;
    sys_lchown = lchown(path: *const u8, uid: u32, gid: u32) -> i32;
    sys_fchown = fchown(fd: i32, uid: u32, gid: u32) -> i32;
    sys_fchownat = fchownat(dirfd: i32, path: *const u8, uid: u32, gid: u32, flags: i32) -> i32;
    sys_symlink = symlink(target: *const u8, link: *const u8) -> i32;
    sys_symlinkat = symlinkat(target: *const u8, dirfd: i32, link: *const u8) -> i32;
    sys_readlink = readlink(path: *const u8, buf: *mut u8, n: usize) -> isize;
    sys_readlinkat = readlinkat(dirfd: i32, path: *const u8, buf: *mut u8, n: usize) -> isize;
    sys_utimensat = utimensat(dirfd: i32, path: *const u8, times: *const u8, flags: i32) -> i32;
    sys_rename = rename(from: *const u8, to: *const u8) -> i32;
    sys_renameat = renameat(fromfd: i32, from: *const u8, tofd: i32, to: *const u8) -> i32;
    sys_link = link(from: *const u8, to: *const u8) -> i32;
    sys_linkat = linkat(fromfd: i32, from: *const u8, tofd: i32, to: *const u8, flags: i32) -> i32;
    sys_dup = dup(fd: i32) -> i32;
    sys_dup2 = dup2(fd: i32, to: i32) -> i32;
    sys_getdirentries64 = __getdirentries64(fd: i32, buf: *mut u8, n: usize, basep: *mut i64) -> isize;
}

#[inline]
pub unsafe fn sys_open(path: *const u8, flags: i32, mode: i32) -> isize {
    errno_ret(open(path, flags, mode) as isize)
}

#[inline]
pub unsafe fn sys_openat(dirfd: i32, path: *const u8, flags: i32, mode: i32) -> isize {
    errno_ret(openat(dirfd, path, flags, mode) as isize)
}

#[inline]
pub unsafe fn sys_fcntl(fd: i32, cmd: i32, arg: isize) -> isize {
    errno_ret(fcntl(fd, cmd, arg) as isize)
}

#[inline]
pub unsafe fn sys_umask(mask: u16) -> u16 {
    umask(mask)
}

/// `getcwd` in the Linux syscall's shape: the length of the path
/// *including* its NUL, or `-errno`. libc's returns the buffer.
pub unsafe fn sys_getcwd(buf: *mut u8, size: usize) -> isize {
    if getcwd(buf, size).is_null() {
        return -(errno() as isize);
    }
    let mut n = 0;
    while *buf.add(n) != 0 {
        n += 1;
    }
    (n + 1) as isize
}

// ─── M9: sockets, poll, kqueue ─────────────────────────────────────────

#[link(name = "System")]
extern "C" {
    fn socket(domain: i32, ty: i32, proto: i32) -> i32;
    fn socketpair(domain: i32, ty: i32, proto: i32, sv: *mut i32) -> i32;
    fn bind(fd: i32, addr: *const u8, len: u32) -> i32;
    fn listen(fd: i32, backlog: i32) -> i32;
    fn accept(fd: i32, addr: *mut u8, len: *mut u32) -> i32;
    fn connect(fd: i32, addr: *const u8, len: u32) -> i32;
    fn setsockopt(fd: i32, level: i32, name: i32, val: *const u8, len: u32) -> i32;
    fn getsockopt(fd: i32, level: i32, name: i32, val: *mut u8, len: *mut u32) -> i32;
    fn getsockname(fd: i32, addr: *mut u8, len: *mut u32) -> i32;
    fn getpeername(fd: i32, addr: *mut u8, len: *mut u32) -> i32;
    fn shutdown(fd: i32, how: i32) -> i32;
    fn sendto(fd: i32, buf: *const u8, n: usize, flags: i32, addr: *const u8, len: u32) -> isize;
    fn recvfrom(fd: i32, buf: *mut u8, n: usize, flags: i32, addr: *mut u8, len: *mut u32) -> isize;
    fn poll(fds: *mut u8, n: u32, timeout: i32) -> i32;
    fn kqueue() -> i32;
    fn kevent(
        kq: i32,
        changes: *const Kevent,
        nchanges: i32,
        events: *mut Kevent,
        nevents: i32,
        timeout: *const u8,
    ) -> i32;
}

/// `struct kevent` — 32 bytes, measured against `<sys/event.h>`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Kevent {
    pub ident: usize,
    pub filter: i16,
    pub flags: u16,
    pub fflags: u32,
    pub data: isize,
    pub udata: usize,
}

pub const EVFILT_READ: i16 = -1;
pub const EVFILT_WRITE: i16 = -2;
pub const EVFILT_USER: i16 = -10;
pub const EV_ADD: u16 = 0x1;
pub const EV_DELETE: u16 = 0x2;
pub const EV_ONESHOT: u16 = 0x10;
pub const EV_CLEAR: u16 = 0x20;
pub const EV_RECEIPT: u16 = 0x40;
pub const EV_ERROR: u16 = 0x4000;
pub const EV_EOF: u16 = 0x8000;
pub const NOTE_TRIGGER: u32 = 0x0100_0000;

libc_ret! {
    sys_socket = socket(domain: i32, ty: i32, proto: i32) -> i32;
    sys_socketpair = socketpair(domain: i32, ty: i32, proto: i32, sv: *mut i32) -> i32;
    sys_bind = bind(fd: i32, addr: *const u8, len: u32) -> i32;
    sys_listen = listen(fd: i32, backlog: i32) -> i32;
    sys_accept = accept(fd: i32, addr: *mut u8, len: *mut u32) -> i32;
    sys_connect = connect(fd: i32, addr: *const u8, len: u32) -> i32;
    sys_setsockopt = setsockopt(fd: i32, level: i32, name: i32, val: *const u8, len: u32) -> i32;
    sys_getsockopt = getsockopt(fd: i32, level: i32, name: i32, val: *mut u8, len: *mut u32) -> i32;
    sys_getsockname = getsockname(fd: i32, addr: *mut u8, len: *mut u32) -> i32;
    sys_getpeername = getpeername(fd: i32, addr: *mut u8, len: *mut u32) -> i32;
    sys_shutdown = shutdown(fd: i32, how: i32) -> i32;
    sys_sendto = sendto(fd: i32, buf: *const u8, n: usize, flags: i32, addr: *const u8, len: u32) -> isize;
    sys_recvfrom = recvfrom(fd: i32, buf: *mut u8, n: usize, flags: i32, addr: *mut u8, len: *mut u32) -> isize;
    sys_poll = poll(fds: *mut u8, n: u32, timeout: i32) -> i32;
    sys_kqueue = kqueue() -> i32;
}

/// `kevent(2)` with an optional relative timeout in nanoseconds
/// (`None` blocks). Returns the event count or `-errno`.
pub unsafe fn sys_kevent(
    kq: i32,
    changes: &[Kevent],
    events: &mut [Kevent],
    timeout_ns: Option<i64>,
) -> isize {
    let ts: [i64; 2];
    let tp = match timeout_ns {
        None => core::ptr::null(),
        Some(ns) => {
            // Darwin rejects a very long timeout with EINVAL; Go caps
            // it at 1e6 s (`runtime/netpoll_kqueue.go:101-105`).
            let ns = ns.max(0);
            ts = [(ns / 1_000_000_000).min(1_000_000), ns % 1_000_000_000];
            ts.as_ptr() as *const u8
        }
    };
    errno_ret(kevent(
        kq,
        changes.as_ptr(),
        changes.len() as i32,
        events.as_mut_ptr(),
        events.len() as i32,
        tp,
    ) as isize)
}

// ─── M6/M8: signals ────────────────────────────────────────────────────

#[link(name = "System")]
extern "C" {
    fn sigaction(sig: i32, new: *const BsdSigaction, old: *mut BsdSigaction) -> i32;
    fn setitimer(which: i32, new: *const u8, old: *mut u8) -> i32;
    fn ioctl(fd: i32, req: u64, ...) -> i32;
    fn pthread_kill(thread: usize, sig: i32) -> i32;
    fn pthread_sigmask(how: i32, set: *const u32, old: *mut u32) -> i32;
}

/// libc's `struct sigaction` — 16 bytes (`<sys/signal.h>`): the
/// handler, a 32-bit `sigset_t`, then `int sa_flags`. No restorer:
/// libSystem supplies its own `_sigtramp` and returns through it.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct BsdSigaction {
    pub handler: usize,
    pub mask: u32,
    pub flags: i32,
}

#[inline]
pub unsafe fn sys_sigaction(sig: i32, new: *const BsdSigaction, old: *mut BsdSigaction) -> isize {
    errno_ret(sigaction(sig, new, old) as isize)
}

#[inline]
pub unsafe fn sys_setitimer(which: i32, new: *const u8, old: *mut u8) -> isize {
    errno_ret(setitimer(which, new, old) as isize)
}

/// `ioctl(2)` — variadic in C, hence the declaration above; the
/// request word is an `unsigned long` on Darwin.
#[inline]
pub unsafe fn sys_ioctl(fd: i32, req: u64, arg: usize) -> isize {
    errno_ret(ioctl(fd, req, arg) as isize)
}

/// `pthread_kill(3)` — 0 or `-errno` (the call returns the error
/// directly rather than through `errno`).
#[inline]
pub unsafe fn sys_pthread_kill(thread: usize, sig: i32) -> isize {
    direct_ret(pthread_kill(thread, sig))
}

/// `pthread_sigmask(3)` over a 32-bit `sigset_t`.
#[inline]
pub unsafe fn sys_pthread_sigmask(how: i32, set: *const u32, old: *mut u32) -> isize {
    direct_ret(pthread_sigmask(how, set, old))
}

// ─── M6: the symboliser's view of its own image ────────────────────────
//
// `runtime::symbolize::macho` reads the main executable's symbol table
// out of the mapped image and its line table out of the dSYM bundle
// beside the executable file. Neither of the two things it needs to
// find them is a syscall:
//
//   * the image's own Mach-O header — `__mh_execute_header`, the symbol
//     ld64 defines at the first byte of `__TEXT` in every executable.
//     Its runtime address minus `__TEXT`'s link-time `vmaddr` is the
//     ASLR slide, so no `_dyld_*` call is needed.
//   * the executable's path. Go reads it from the `executable_path=`
//     string the kernel places after `envp` (`runtime/os_darwin.go:477-487`,
//     `sysargs`); goish's `main` is not guaranteed that vector's layout
//     past `envp`, so it asks dyld with `_NSGetExecutablePath(3)`.

#[link(name = "System")]
extern "C" {
    #[link_name = "\x01__mh_execute_header"]
    static MH_EXECUTE_HEADER: u8;
    fn _NSGetExecutablePath(buf: *mut u8, bufsize: *mut u32) -> i32;
}

/// The main executable's `mach_header_64`, as mapped. Valid for the
/// life of the process.
#[inline]
pub fn sys_mh_execute_header() -> *const u8 {
    // Taking a static's address reads nothing, so it is safe even for
    // an `extern` one.
    core::ptr::addr_of!(MH_EXECUTE_HEADER)
}

/// `_NSGetExecutablePath` into `buf`, NUL-terminated. Returns the
/// length without the NUL, or `-1` when `buf` is too small (dyld then
/// reports the size it needs; callers here pass `PATH_MAX` and do not
/// retry).
#[inline]
pub unsafe fn sys_executable_path(buf: &mut [u8]) -> isize {
    let mut size = buf.len() as u32;
    if _NSGetExecutablePath(buf.as_mut_ptr(), &mut size) != 0 {
        return -1;
    }
    let mut n = 0usize;
    while n < buf.len() && buf[n] != 0 {
        n += 1;
    }
    n as isize
}

// ─── os/exec: fork, exec, wait, pipe ───────────────────────────────────
//
// The process-creation primitives, as Go's darwin `syscall` package
// binds them (`syscall/zsyscall_darwin_arm64.go` — `libc_fork` :1784,
// `libc_wait4` :54, `libc_pipe` :379). None of them is variadic, so the
// plain declarations are correct under Apple's arm64 variadic rule.
//
// `_exit` is the one deliberate departure: Go's child exits through
// `libc_exit` (`exit(3)`, :1812, reached from `exec_libc2.go:292`).
// `exit(3)` runs `atexit` handlers and flushes stdio, and in a child
// forked from a multi-threaded process any lock those take may be held
// by a thread that did not survive the fork. POSIX lists `_exit`, not
// `exit`, as async-signal-safe — the only kind of call permitted
// between `fork` and `exec` — so the child uses it. The parent's own
// whole-process exit stays on `exit(3)` (`sys_exit` above), as Go's.

#[link(name = "System")]
extern "C" {
    fn fork() -> i32;
    fn _exit(code: i32) -> !;
    fn execve(path: *const u8, argv: *const *const u8, envp: *const *const u8) -> i32;
    fn wait4(pid: i32, status: *mut i32, options: i32, rusage: *mut u8) -> i32;
    fn pipe(fds: *mut i32) -> i32;
}

libc_ret! {
    sys_fork = fork() -> i32;
    sys_execve = execve(path: *const u8, argv: *const *const u8, envp: *const *const u8) -> i32;
    sys_wait4 = wait4(pid: i32, status: *mut i32, options: i32, rusage: *mut u8) -> i32;
    sys_pipe = pipe(fds: *mut i32) -> i32;
}

/// `_exit(2)` — leave a forked child without running `atexit` handlers
/// or touching stdio. See the note at the top of this section.
#[inline]
pub unsafe fn sys_exit_child(code: i32) -> ! {
    _exit(code)
}
