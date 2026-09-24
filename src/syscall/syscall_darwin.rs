// syscall_darwin — Go's `syscall` package on macOS/arm64.
//
// Go: `syscall/syscall_darwin.go` + `zsyscall_darwin_arm64.go`. The
// shape is the same as the Linux sibling next door and the mechanism
// underneath is not: there is **no `zsysnum` table**, because libSystem
// is the ABI on this platform and there are no numbers to tabulate. The
// primitives come from `crate::sys` as named functions.
//
// ─── What M1 implements, and what it does not ──────────────────────────
//
// M1 is boot + `examples/hello.rs`: `_start` → `__goish_rt0` → args →
// flags → the dlmalloc bootstrap heap → the user's `main` → exit. That
// needs `Write`, `Read`, `Exit`, `Mmap`, `Munmap`, `Mprotect` and
// `Madvise`, and those are real below.
//
// The other ~80 wrappers exist so the 271k-line tree above this module
// compiles, and every one of them calls `todo()`, which prints the
// wrapper's name and the milestone that owns it and exits 2. That is
// deliberately louder than `unimplemented!()`: the message says
// *`goish: syscall::Socket is not implemented on darwin/arm64 yet
// (M9)`*, so the first example that walks off the M1 path names its own
// next milestone instead of producing a bare panic location.
//
// Each `todo` carries the milestone from the port plan's ladder:
//
//   M2  memory, 16 KiB pages, the file surface
//   M3  time, entropy, CPU count
//   M4  threads + TLS
//   M5  context switch (AAPCS64)
//   M6  signals: SIGSEGV + backtrace
//   M7  futex → pthread condvar
//   M8  async preemption
//   M9  kqueue netpoller, sockets
//
// `os/exec` sat outside the ladder (the plan's "Explicitly out of
// scope": `fork` + exec is translatable, `pipe2` is not, and
// fork-in-a-threaded-process is stricter here). It is implemented now,
// in its own section at the end of this file.

use crate::sys;

// The constant table and the struct layouts, both generated from the
// SDK headers — see their own file headers for the method.
#[path = "zerrors_darwin_arm64.rs"]
mod zerrors_darwin_arm64;
pub use zerrors_darwin_arm64::*;

#[path = "ztypes_darwin_arm64.rs"]
mod ztypes_darwin_arm64;
pub use ztypes_darwin_arm64::*;

/// Report an unimplemented Darwin wrapper and exit.
///
/// Not `unimplemented!()`: this runs before `runtime::symbolize` exists
/// on the target (M6), so a panic location would be a file and line with
/// no backtrace behind it. The name plus the milestone is strictly more
/// information and costs a few bytes of `.rodata`.
#[cold]
#[inline(never)]
fn todo(what: &str, milestone: &str) -> ! {
    unsafe {
        let pre = b"goish: syscall::";
        sys::sys_write(STDERR, pre.as_ptr(), pre.len());
        sys::sys_write(STDERR, what.as_ptr(), what.len());
        let mid = b" is not implemented on darwin/arm64 yet (";
        sys::sys_write(STDERR, mid.as_ptr(), mid.len());
        sys::sys_write(STDERR, milestone.as_ptr(), milestone.len());
        let end = b")\n";
        sys::sys_write(STDERR, end.as_ptr(), end.len());
        sys::sys_exit(2)
    }
}

// ─── raw syscall numbers and the `syscallN` entry points ───────────────
//
// Both exist only so the handful of call sites that bypassed the
// wrappers keep compiling. There are 27 of them, all outside this
// module, and the port plan already flags them as latent bugs on Linux
// too — `net/dnsclient.rs:60` hardcodes the literal `228` for
// `clock_gettime` rather than using `SYS_CLOCK_GETTIME`.
//
// On this target they are not bugs, they are impossibilities: libSystem
// has no "call number N" entry point to route them through. The numbers
// are poison and the entry points abort, so the fix — converting each
// site to the Go-shaped wrapper above it — is forced rather than
// deferred the first time one of those paths runs.

/// Poison. Every `SYS_*` below is one of these; see the note above.
const POISON_SYS: usize = !0;

pub const SYS_READ: usize = POISON_SYS;
pub const SYS_WRITE: usize = POISON_SYS;
pub const SYS_CLOSE: usize = POISON_SYS;
pub const SYS_EXIT: usize = POISON_SYS;
pub const SYS_FSYNC: usize = POISON_SYS;
pub const SYS_UNAME: usize = POISON_SYS;
pub const SYS_NEWFSTATAT: usize = POISON_SYS;
pub const SYS_GETSOCKNAME: usize = POISON_SYS;
pub const SYS_SETSOCKOPT: usize = POISON_SYS;
pub const SYS_SENDTO: usize = POISON_SYS;
pub const SYS_RECVFROM: usize = POISON_SYS;

macro_rules! no_raw_syscall {
    ($($name:ident($($arg:ident),*);)*) => {$(
        /// Raw syscall entry point. **Unavailable on Darwin** — see the
        /// note above `POISON_SYS`.
        #[inline]
        #[allow(unused_variables)]
        pub unsafe fn $name(n: usize, $($arg: usize),*) -> isize {
            todo("syscallN", "convert this call site to its wrapper")
        }
    )*};
}

no_raw_syscall! {
    syscall0();
    syscall1(a1);
    syscall2(a1, a2);
    syscall3(a1, a2, a3);
    syscall4(a1, a2, a3, a4);
    syscall6(a1, a2, a3, a4, a5, a6);
}

// ─── the M1 primitives ─────────────────────────────────────────────────

/// Write up to `n` bytes from `p` to file descriptor `fd`.
///
/// Returns the byte count, or a negative `-errno` — goish's ABI, which
/// `crate::sys` adapts Darwin's `-1`-plus-`errno` convention into. Every
/// caller is therefore unchanged from Linux.
#[allow(non_snake_case)]
pub fn Write(fd: i32, p: *const u8, n: usize) -> isize {
    unsafe { sys::sys_write(fd, p, n) }
}

/// Read up to `n` bytes from `fd` into `p`.
#[allow(non_snake_case)]
pub fn Read(fd: i32, p: *mut u8, n: usize) -> isize {
    unsafe { sys::sys_read(fd, p, n) }
}

/// Terminate the process.
///
/// Linux's `Exit` is `exit_group(2)`, which takes every thread down
/// with it. libSystem's `exit(3)` has the same whole-process effect,
/// so the contract holds — Go calls it the same way
/// (`runtime/sys_darwin.go`, `exit` → `libc_exit`).
#[allow(non_snake_case)]
pub fn Exit(code: i32) -> ! {
    unsafe { sys::sys_exit(code) }
}

/// `mmap(2)`. Returns the mapping address, or `MAP_FAILED`.
#[allow(non_snake_case)]
pub fn Mmap(addr: *mut u8, length: usize, prot: i32, flags: i32, fd: i32, offset: i64) -> *mut u8 {
    let r = unsafe { sys::sys_mmap(addr, length, prot, flags, fd, offset) };
    if r < 0 {
        MAP_FAILED
    } else {
        r as *mut u8
    }
}

/// `munmap(2)`.
#[allow(non_snake_case)]
pub fn Munmap(addr: *mut u8, length: usize) -> isize {
    unsafe { sys::sys_munmap(addr, length) }
}

/// `mprotect(2)`.
#[allow(non_snake_case)]
pub fn Mprotect(addr: *mut u8, length: usize, prot: i32) -> isize {
    unsafe { sys::sys_mprotect(addr, length, prot) }
}

/// `madvise(2)`.
///
/// **Passing `MADV_DONTNEED` here does not do what it does on Linux.**
/// See the constant's note in `zerrors_darwin_arm64.rs`: the Darwin
/// release path is `MADV_FREE_REUSABLE` / `MADV_FREE_REUSE`
/// (`runtime/mem_darwin.go:23-34`). The wrapper stays neutral; M2 picks.
#[allow(non_snake_case)]
pub fn Madvise(addr: *mut u8, length: usize, advice: i32) -> isize {
    unsafe { sys::sys_madvise(addr, length, advice) }
}

// ─── byte order ────────────────────────────────────────────────────────
//
// Pure arithmetic, identical on both targets. Duplicated rather than
// shared for the same reason the `Errno` impls are: the file is the
// whole of the target's surface.

/// Convert host-order u16 to network byte order (big-endian).
#[inline]
pub const fn htons(x: u16) -> u16 {
    x.to_be()
}

/// Convert network-order u16 to host order.
#[inline]
pub const fn ntohs(x: u16) -> u16 {
    u16::from_be(x)
}

/// Convert host-order u32 to network byte order (big-endian).
#[inline]
pub const fn htonl(x: u32) -> u32 {
    x.to_be()
}

/// Convert network-order u32 to host order.
#[inline]
pub const fn ntohl(x: u32) -> u32 {
    u32::from_be(x)
}

// ─── SockaddrIn constructors ───────────────────────────────────────────
//
// Same names and signatures as the Linux side. They set `sin_len`,
// which is the field BSD has and Linux does not — which is exactly why
// callers must go through them rather than writing struct literals.

impl SockaddrIn {
    /// Build an `AF_INET` sockaddr for `port` on the wildcard address.
    pub const fn any(port: u16) -> Self {
        SockaddrIn {
            sin_len: core::mem::size_of::<SockaddrIn>() as u8,
            sin_family: AF_INET as u8,
            sin_port: htons(port),
            sin_addr: INADDR_ANY,
            _pad: [0; 8],
        }
    }

    /// Build an `AF_INET` sockaddr for `port` on `127.0.0.1`.
    pub const fn loopback(port: u16) -> Self {
        SockaddrIn {
            sin_len: core::mem::size_of::<SockaddrIn>() as u8,
            sin_family: AF_INET as u8,
            sin_port: htons(port),
            sin_addr: htonl(0x7F00_0001),
            _pad: [0; 8],
        }
    }

    /// Build from IPv4 octets and a host-order port.
    pub const fn ipv4(octets: [u8; 4], port: u16) -> Self {
        let addr = ((octets[0] as u32) << 24)
            | ((octets[1] as u32) << 16)
            | ((octets[2] as u32) << 8)
            | (octets[3] as u32);
        Self::ipv4_host(addr, port)
    }

    /// Build from a host-order IPv4 address and a host-order port.
    pub const fn ipv4_host(addr: u32, port: u16) -> Self {
        SockaddrIn {
            sin_len: core::mem::size_of::<SockaddrIn>() as u8,
            sin_family: AF_INET as u8,
            sin_port: htons(port),
            sin_addr: htonl(addr),
            _pad: [0; 8],
        }
    }

    /// Extract host-order port.
    pub const fn port_host(&self) -> u16 {
        ntohs(self.sin_port)
    }
}

impl RawConn {
    pub(crate) fn __from_fd(fd: i32) -> RawConn {
        RawConn { fd }
    }

    /// `RawConn.Control(f func(fd uintptr)) error`.
    #[allow(non_snake_case)]
    pub fn Control<F: Fn(crate::uintptr)>(&self, f: F) -> crate::error {
        f(self.fd as crate::uintptr);
        crate::errors::nil
    }
}

impl FileHandle {
    /// `unix.NewFileHandle(handleType, bytes)`. Linux-only in effect —
    /// `NameToHandleAt` never produces one on this target.
    pub fn New(handle_type: i32, bytes: crate::slice<u8>) -> FileHandle {
        let _ = (handle_type, &bytes);
        todo("NameToHandleAt", "Linux-only")
    }
    /// `FileHandle.Type()`.
    pub fn Type(&self) -> i32 {
        todo("FileHandle::Type", "Linux-only")
    }
    /// `FileHandle.Bytes()`.
    pub fn Bytes(&self) -> crate::slice<u8> {
        todo("FileHandle::Bytes", "Linux-only")
    }
    /// `FileHandle.Size()`.
    pub fn Size(&self) -> crate::int {
        todo("FileHandle::Size", "Linux-only")
    }
}

/// The userspace `rt_sigreturn` trampoline address for `sa_restorer`.
///
/// **Zero on Darwin, and correctly so.** BSD `sigaction` has no
/// `sa_restorer` field: the kernel returns from a handler through
/// libSystem's own trampoline, and there is nothing for userspace to
/// supply. The `Sigaction` literals across `runtime/` still name the
/// field, so the function has to exist; `RtSigaction` on this target
/// ignores what it returns.
#[allow(non_snake_case)]
pub fn sigreturn_restorer() -> usize {
    0
}

/// `clone(2)`. **No Darwin analogue** — threads are created with
/// `pthread_create` (Go: `runtime/os_darwin.go:233-258`). M4.
///
/// Kept under the Linux name and signature because `sched::spawn_worker_m`
/// and `sysmon::start_sysmon` both name it; M4 replaces the call sites
/// rather than this stub.
#[allow(non_snake_case, unused_variables)]
pub unsafe extern "C" fn Clone(
    _flags: u64,
    _child_stack: *mut u8,
    _child_entry: extern "C" fn() -> !,
    _tls: u64,
) -> i64 {
    todo("Clone", "M4")
}

// ─── everything else ───────────────────────────────────────────────────
//
// Generated from the Linux wrappers' signatures so the two surfaces
// cannot drift: same names, same argument and return types, bodies
// replaced by `todo()`.
#[allow(non_snake_case)]
pub fn Ioctl(fd: i32, req: usize, arg: usize) -> isize {
    unsafe { sys::sys_ioctl(fd, req as u64, arg) }
}

#[allow(non_snake_case)]
pub fn Open(path: *const u8, flags: i32, mode: i32) -> i32 {
    unsafe { sys::sys_open(path, flags, mode) as i32 }
}

#[allow(non_snake_case)]
pub fn Close(fd: i32) -> i32 {
    unsafe { sys::sys_close(fd) as i32 }
}

#[allow(non_snake_case)]
pub fn Fstat(fd: i32, out: &mut Stat_t) -> i32 {
    unsafe { sys::sys_fstat(fd, out as *mut Stat_t as *mut u8) as i32 }
}

#[allow(non_snake_case)]
pub fn Stat(path: *const u8, out: &mut Stat_t) -> i32 {
    unsafe { sys::sys_stat(path, out as *mut Stat_t as *mut u8) as i32 }
}

#[allow(non_snake_case)]
pub fn Lstat(path: *const u8, out: &mut Stat_t) -> i32 {
    unsafe { sys::sys_lstat(path, out as *mut Stat_t as *mut u8) as i32 }
}

#[allow(non_snake_case)]
pub fn Lseek(fd: i32, offset: i64, whence: i32) -> i64 {
    unsafe { sys::sys_lseek(fd, offset, whence) as i64 }
}

#[allow(non_snake_case)]
pub fn Pread64(fd: i32, buf: *mut u8, count: usize, offset: i64) -> isize {
    unsafe { sys::sys_pread(fd, buf, count, offset) }
}

#[allow(non_snake_case)]
pub fn Pwrite64(fd: i32, buf: *const u8, count: usize, offset: i64) -> isize {
    unsafe { sys::sys_pwrite(fd, buf, count, offset) }
}

#[allow(non_snake_case)]
pub fn Ftruncate(fd: i32, length: i64) -> i32 {
    unsafe { sys::sys_ftruncate(fd, length) as i32 }
}

#[allow(non_snake_case)]
pub fn Flock(fd: crate::types::int, operation: crate::types::int) -> crate::errors::error {
    let rc = unsafe { sys::sys_flock(fd as i32, operation as i32) } as i32;
    if rc >= 0 {
        return crate::errors::nil;
    }
    Errno(-rc).into()
}

#[allow(non_snake_case)]
pub fn Mkdir(path: *const u8, mode: u32) -> i32 {
    unsafe { sys::sys_mkdir(path, mode as u16) as i32 }
}

#[allow(non_snake_case)]
pub fn Unlink(path: *const u8) -> i32 {
    unsafe { sys::sys_unlink(path) as i32 }
}

#[allow(non_snake_case)]
pub fn Rmdir(path: *const u8) -> i32 {
    unsafe { sys::sys_rmdir(path) as i32 }
}

#[allow(non_snake_case)]
pub fn Getcwd(buf: *mut u8, size: usize) -> isize {
    unsafe { sys::sys_getcwd(buf, size) }
}

#[allow(non_snake_case)]
pub fn Chdir(path: *const u8) -> i32 {
    unsafe { sys::sys_chdir(path) as i32 }
}

#[allow(non_snake_case)]
pub fn Chmod(path: *const u8, mode: u32) -> i32 {
    unsafe { sys::sys_chmod(path, mode as u16) as i32 }
}

#[allow(non_snake_case)]
pub fn Fchmod(fd: i32, mode: u32) -> i32 {
    unsafe { sys::sys_fchmod(fd, mode as u16) as i32 }
}

#[allow(non_snake_case)]
pub fn Symlink(oldname: *const u8, newname: *const u8) -> i32 {
    unsafe { sys::sys_symlink(oldname, newname) as i32 }
}

#[allow(non_snake_case)]
pub fn Readlink(path: *const u8, buf: *mut u8, bufsiz: usize) -> isize {
    unsafe { sys::sys_readlink(path, buf, bufsiz) }
}

#[allow(non_snake_case)]
pub fn Utimensat(dirfd: i32, path: *const u8, times: *const Timespec, flags: i32) -> i32 {
    unsafe { sys::sys_utimensat(dirfd, path, times as *const u8, flags) as i32 }
}

#[allow(non_snake_case)]
pub fn Rename(oldpath: *const u8, newpath: *const u8) -> i32 {
    unsafe { sys::sys_rename(oldpath, newpath) as i32 }
}

#[allow(non_snake_case)]
pub fn Link(oldpath: *const u8, newpath: *const u8) -> i32 {
    unsafe { sys::sys_link(oldpath, newpath) as i32 }
}

#[allow(non_snake_case)]
pub fn Truncate(path: *const u8, length: i64) -> i32 {
    unsafe { sys::sys_truncate(path, length) as i32 }
}

#[allow(non_snake_case)]
pub fn Chown(path: *const u8, uid: i32, gid: i32) -> i32 {
    unsafe { sys::sys_chown(path, uid as u32, gid as u32) as i32 }
}

#[allow(non_snake_case)]
pub fn Lchown(path: *const u8, uid: i32, gid: i32) -> i32 {
    unsafe { sys::sys_lchown(path, uid as u32, gid as u32) as i32 }
}

/// `uname(3)` — 0 or `-errno`. Darwin's `Utsname` is five 256-byte
/// fields with no `domainname` (`ztypes_darwin_arm64.rs`).
#[allow(non_snake_case)]
pub fn Uname(buf: &mut Utsname) -> i32 {
    unsafe { sys::sys_uname(buf as *mut Utsname as *mut u8) as i32 }
}

/// `getrandom(2)`'s contract over `arc4random_buf(3)`, which is what Go's
/// darwin `readRandom` calls (`runtime/os_darwin.go`). It cannot fail
/// and never blocks, so every flag — `GRND_NONBLOCK`, `GRND_RANDOM`,
/// `GRND_INSECURE` — is already satisfied and the full length is
/// always returned.
#[allow(non_snake_case)]
pub fn Getrandom(buf: *mut u8, buflen: usize, flags: u32) -> i64 {
    let _ = flags;
    unsafe { sys::sys_arc4random_buf(buf, buflen) };
    buflen as i64
}

#[allow(non_snake_case)]
pub fn Getdents64(fd: i32, buf: *mut u8, buflen: usize) -> i64 {
    getdents64(fd, buf, buflen)
}

#[allow(non_snake_case)]
pub fn Recvfrom(fd: i32, buf: *mut u8, len: usize, flags: i32) -> isize {
    unsafe { sys::sys_recvfrom(fd, buf, len, flags, core::ptr::null_mut(), core::ptr::null_mut()) }
}

/// `clock_gettime(2)` — read `clk` into `tp`; 0 or `-errno`.
///
/// Truthful to Darwin's clock ids, which is not the same as truthful to
/// the caller's intent: `CLOCK_MONOTONIC` here counts time asleep
/// (measured ~5.4 days ahead of `CLOCK_UPTIME_RAW` on a laptop that
/// had slept), where Linux's does not. goish's own monotonic reads go
/// through `runtime::sysmon::monotonic_ns`, which picks the right id.
#[allow(non_snake_case)]
pub fn ClockGettime(clk: i32, tp: *mut Timespec) -> isize {
    unsafe { sys::sys_clock_gettime(clk, tp as *mut u8) }
}

/// `nanosleep(2)`. Same contract as Linux: 0, or `-errno` (`-EINTR`
/// with `rem` filled if a signal interrupted it).
#[allow(non_snake_case)]
pub fn Nanosleep(req: *const Timespec, rem: *mut Timespec) -> isize {
    unsafe { sys::sys_nanosleep(req as *const u8, rem as *mut u8) }
}

/// The calling thread's id, for `M::procid`.
///
/// Darwin has no `gettid`. This is `pthread_threadid_np`'s 64-bit
/// system-wide id truncated to Linux's `pid_t` width — unique in
/// practice for a process's lifetime, and **diagnostic only** here:
/// Linux signals a thread through this number (`tgkill`), Darwin
/// signals it through its `pthread_t` (`pthread_kill`, Go's `signalM`),
/// which `MStorage::pthread` carries separately. Go stores
/// `pthread_self()` in `m.procid` (`runtime/os_darwin.go`, `minit`);
/// goish keeps `procid` an `i32` on every target and the handle apart.
#[allow(non_snake_case)]
pub fn Gettid() -> i32 {
    unsafe { sys::sys_thread_id() as i32 }
}

/// `getpid(2)` — process id. Cannot fail.
#[allow(non_snake_case)]
pub fn Getpid() -> i32 {
    unsafe { sys::sys_getpid() }
}

/// `getuid(2)`. Cannot fail; returned as `i32` like the Linux
/// wrapper, which is how every caller already reads it.
#[allow(non_snake_case)]
pub fn Getuid() -> i32 {
    unsafe { sys::sys_getuid() as i32 }
}

/// `getgid(2)`. Cannot fail; returned as `i32` like the Linux
/// wrapper, which is how every caller already reads it.
#[allow(non_snake_case)]
pub fn Getgid() -> i32 {
    unsafe { sys::sys_getgid() as i32 }
}

/// `geteuid(2)`. Cannot fail; returned as `i32` like the Linux
/// wrapper, which is how every caller already reads it.
#[allow(non_snake_case)]
pub fn Geteuid() -> i32 {
    unsafe { sys::sys_geteuid() as i32 }
}

/// `getegid(2)`. Cannot fail; returned as `i32` like the Linux
/// wrapper, which is how every caller already reads it.
#[allow(non_snake_case)]
pub fn Getegid() -> i32 {
    unsafe { sys::sys_getegid() as i32 }
}

/// `getppid(2)` — parent process id. Cannot fail.
#[allow(non_snake_case)]
pub fn Getppid() -> i32 {
    unsafe { sys::sys_getppid() }
}

/// `getgroups(2)` — count on success, `-errno` on failure. `gid_t` is
/// `u32` here as on Linux.
#[allow(non_snake_case)]
pub fn Getgroups(size: i32, list: *mut u32) -> isize {
    unsafe { sys::sys_getgroups(size, list) }
}

/// `kill(2)` — 0 or `-errno`. The signal numbers are Darwin's
/// (`zerrors_darwin_arm64.rs`), so callers spelling them by name are
/// portable and callers spelling them by number are not.
#[allow(non_snake_case)]
pub fn Kill(pid: i32, sig: i32) -> isize {
    unsafe { sys::sys_kill(pid, sig) }
}

#[allow(non_snake_case, unused_variables)]
pub fn Tgkill(tgid: i32, tid: i32, sig: i32) -> isize {
    todo("Tgkill", "M8")
}

#[allow(non_snake_case)]
pub unsafe fn RtSigaction(
    sig: i32,
    new: *const Sigaction,
    old: *mut Sigaction,
) -> isize {
    let mut bnew = sys::BsdSigaction::default();
    let np = if new.is_null() {
        core::ptr::null()
    } else {
        let n = &*new;
        bnew.handler = n.sa_handler;
        bnew.mask = n.sa_mask as u32;
        bnew.flags = n.sa_flags as i32;
        &bnew as *const sys::BsdSigaction
    };
    let mut bold = sys::BsdSigaction::default();
    let op = if old.is_null() { core::ptr::null_mut() } else { &mut bold as *mut sys::BsdSigaction };
    let r = sys::sys_sigaction(sig, np, op);
    if r == 0 && !old.is_null() {
        *old = Sigaction {
            sa_handler: bold.handler,
            sa_flags: bold.flags as u32 as u64,
            sa_restorer: 0,
            sa_mask: bold.mask as u64,
        };
    }
    r
}

/// `sigaltstack(2)`. Real from M4, ahead of the M6 handlers that use
/// it, because `setup_main_tls` registers every M's alt stack as part
/// of making the M — and it is one libSystem call. The struct is the
/// BSD layout (`ztypes_darwin_arm64.rs`); callers that fill it by field
/// name are portable.
#[allow(non_snake_case)]
pub unsafe fn Sigaltstack(new: *const SigaltstackT, old: *mut SigaltstackT) -> isize {
    sys::sys_sigaltstack(new as *const u8, old as *mut u8)
}

/// `sched_yield(2)`.
#[allow(non_snake_case)]
pub fn SchedYield() -> isize {
    unsafe { sys::sys_sched_yield() }
}

/// `futex(2)`'s two private operations, over the kernel's `__ulock`
/// wait queue (M7).
///
/// Go's darwin port parks Ms on a `pthread_cond` instead
/// (`runtime/os_darwin.go:31-92`, `semasleep`/`semawakeup`). goish
/// keeps its futex-shaped `Note` and sysmon nap, so the wrapper is the
/// seam — and `sysmon::wake` is called from a signal handler, where a
/// ulock wake (one syscall) is async-signal-safe and
/// `pthread_cond_signal` is not.
///
/// `ts` is a relative timeout, as for `FUTEX_WAIT`. Returns 0 or
/// `-errno`, for WAKE the number woken (0 or 1; `val > 1` wakes all).
#[allow(non_snake_case)]
pub fn Futex(
    addr: *const u32,
    op: i32,
    val: u32,
    ts: *const Timespec,
) -> isize {
    match op {
        FUTEX_WAIT_PRIVATE => {
            let ns = if ts.is_null() {
                0
            } else {
                let t = unsafe { &*ts };
                // 0 means "forever" to the kernel, so a zero-length
                // wait is rounded up to one nanosecond.
                ((t.tv_sec as u64) * 1_000_000_000 + t.tv_nsec as u64).max(1)
            };
            unsafe { sys::sys_ulock_wait(addr, val, ns) }
        }
        FUTEX_WAKE_PRIVATE => unsafe { sys::sys_ulock_wake(addr, val > 1) },
        _ => -(ENOSYS.0 as isize),
    }
}

/// Start an OS thread running `entry` on the caller-owned stack
/// `[stack_base, stack_base + size)`, with its thread pointer already
/// set to `tls` — Darwin's spelling of `Clone(CLONE_THREAD_FLAGS, …)`.
///
/// `clone(2)` plants the thread pointer atomically with the thread
/// (`CLONE_SETTLS`); `pthread_create` has no equivalent, so a
/// trampoline sets the TSD slot before `entry` runs — and before
/// anything takes a `SpinLock`, whose lock count lives behind it.
/// Returns the `pthread_t`, or `-errno`.
#[allow(non_snake_case)]
pub unsafe fn NewThread(
    stack_base: *mut u8,
    size: usize,
    entry: extern "C" fn() -> !,
    tls: usize,
) -> isize {
    #[repr(C)]
    struct Start {
        entry: extern "C" fn() -> !,
        tls: usize,
    }
    extern "C" fn trampoline(arg: *mut u8) -> *mut u8 {
        // Copy out before the thread pointer exists; the box is freed
        // after, since freeing reaches the allocator's per-M state.
        let (entry, tls) = unsafe {
            let s = &*(arg as *const Start);
            (s.entry, s.tls)
        };
        unsafe {
            crate::runtime::sched::tls::set_base(tls);
            drop(alloc::boxed::Box::from_raw(arg as *mut Start));
        }
        entry()
    }
    let arg = alloc::boxed::Box::into_raw(alloc::boxed::Box::new(Start { entry, tls })) as *mut u8;
    let r = sys::sys_pthread_spawn(stack_base, size, trampoline, arg);
    if r < 0 {
        drop(alloc::boxed::Box::from_raw(arg as *mut Start));
    }
    r
}

#[allow(non_snake_case, unused_variables)]
pub fn SchedGetaffinity(pid: i32, cpusetsize: usize, mask: *mut u8) -> isize {
    todo("SchedGetaffinity", "M3")
}

/// End the calling thread (not the process). The exit code has no
/// Darwin meaning for a detached pthread and is dropped.
#[allow(non_snake_case, unused_variables)]
pub fn ExitThread(code: i32) -> ! {
    unsafe { sys::sys_pthread_exit() }
}

#[allow(non_snake_case)]
pub fn Socket(domain: i32, type_: i32, protocol: i32) -> i32 {
    socket_with_flags(domain, type_, protocol)
}

#[allow(non_snake_case)]
pub fn Bind(fd: i32, addr: *const SockaddrIn, addrlen: u32) -> i32 {
    unsafe { sys::sys_bind(fd, addr as *const u8, addrlen) as i32 }
}

#[allow(non_snake_case)]
pub fn Listen(fd: i32, backlog: i32) -> i32 {
    unsafe { sys::sys_listen(fd, backlog) as i32 }
}

#[allow(non_snake_case)]
pub fn Accept4(
    fd: i32,
    addr: *mut SockaddrIn,
    addrlen: *mut u32,
    flags: i32,
) -> i32 {
    accept_with_flags(fd, addr as *mut u8, addrlen, flags)
}

#[allow(non_snake_case)]
pub fn Connect(fd: i32, addr: *const SockaddrIn, addrlen: u32) -> i32 {
    unsafe { sys::sys_connect(fd, addr as *const u8, addrlen) as i32 }
}

#[allow(non_snake_case)]
pub fn Setsockopt(
    fd: i32,
    level: i32,
    name: i32,
    val: *const u8,
    len: u32,
) -> i32 {
    unsafe { sys::sys_setsockopt(fd, level, name, val, len) as i32 }
}

#[allow(non_snake_case)]
pub fn SetsockoptInt(fd: crate::int, level: crate::int, opt: crate::int, value: crate::int) -> crate::error {
    let n: i32 = value as i32;
    let rc = Setsockopt(
        fd as i32,
        level as i32,
        opt as i32,
        &n as *const i32 as *const u8,
        core::mem::size_of::<i32>() as u32,
    );
    if rc < 0 {
        return Errno(-rc).into();
    }
    crate::errors::nil
}

#[allow(non_snake_case)]
pub fn Getsockopt(
    fd: i32,
    level: i32,
    name: i32,
    val: *mut u8,
    len: *mut u32,
) -> i32 {
    unsafe { sys::sys_getsockopt(fd, level, name, val, len) as i32 }
}

#[allow(non_snake_case)]
pub fn Shutdown(fd: i32, how: i32) -> i32 {
    unsafe { sys::sys_shutdown(fd, how) as i32 }
}

#[allow(non_snake_case)]
pub fn Fcntl(fd: i32, cmd: i32, arg: i32) -> i32 {
    unsafe { sys::sys_fcntl(fd, cmd, arg as isize) as i32 }
}

#[allow(non_snake_case)]
pub fn EpollCreate1(flags: i32) -> i32 {
    epoll_create1(flags)
}

#[allow(non_snake_case)]
pub fn EpollCtl(
    epfd: i32,
    op: i32,
    fd: i32,
    event: *mut EpollEvent,
) -> i32 {
    epoll_ctl(epfd, op, fd, event)
}

// ─── Linux-only kernel interfaces ──────────────────────────────────────
//
// eventfd, inotify, fanotify and name_to_handle_at have no Darwin
// counterpart, and Go does not offer them there either (they live in
// `golang.org/x/sys/unix` under `//go:build linux`). They answer ENOSYS
// rather than abort, so a caller probing for them can fall back.

#[allow(non_snake_case, unused_variables)]
pub fn Eventfd(initval: u32, flags: i32) -> i32 {
    -(ENOSYS.0)
}

#[allow(non_snake_case)]
pub fn EpollPwait(
    epfd: i32,
    events: *mut EpollEvent,
    maxevents: i32,
    timeout_ms: i32,
    sigmask: *const u8,
    sigsetsize: usize,
) -> i32 {
    // No signal mask to swap: the netpoller passes none.
    let _ = (sigmask, sigsetsize);
    epoll_pwait(epfd, events, maxevents, timeout_ms)
}

#[allow(non_snake_case, unused_variables)]
pub fn InotifyInit1(flags: crate::int) -> (crate::int, crate::error) {
    (-1, ENOSYS.into())
}

#[allow(non_snake_case, unused_variables)]
pub fn InotifyAddWatch<P: Into<crate::string>>(
    fd: crate::int,
    pathname: P,
    mask: u32,
) -> (crate::int, crate::error) {
    (-1, ENOSYS.into())
}

#[allow(non_snake_case, unused_variables)]
pub fn InotifyRmWatch(fd: crate::int, watchdesc: u32) -> (crate::int, crate::error) {
    (-1, ENOSYS.into())
}

#[allow(non_snake_case, unused_variables)]
pub fn FanotifyInit(flags: u32, event_f_flags: u32) -> (crate::int, crate::error) {
    (-1, ENOSYS.into())
}

#[allow(non_snake_case, unused_variables)]
pub fn FanotifyMark<P: Into<crate::string>>(
    fd: crate::int,
    flags: u32,
    mask: u64,
    dirFd: crate::int,
    pathname: P,
) -> crate::error {
    ENOSYS.into()
}

#[allow(non_snake_case, unused_variables)]
pub fn NameToHandleAt<P: Into<crate::string>>(
    dirfd: crate::int,
    path: P,
    flags: crate::int,
) -> (FileHandle, crate::int, crate::error) {
    (FileHandle { handle_type: 0, bytes: crate::slice::new() }, 0, ENOSYS.into())
}

#[allow(non_snake_case)]
pub fn Poll(fds: &mut [PollFd], timeout: crate::int) -> (crate::int, crate::error) {
    let rc = unsafe { sys::sys_poll(fds.as_mut_ptr() as *mut u8, fds.len() as u32, timeout as i32) };
    if rc < 0 {
        return (0, Errno(-(rc as i32)).into());
    }
    (rc as crate::int, crate::errors::nil)
}

#[allow(non_snake_case)]
pub fn Statfs<P: Into<crate::string>>(path: P, buf: &mut Statfs_t) -> crate::error {
    let p = __c_path(path.into());
    let rc = unsafe { sys::sys_statfs(p.as_ptr(), buf as *mut Statfs_t as *mut u8) };
    if rc < 0 {
        return Errno(-(rc as i32)).into();
    }
    crate::errors::nil
}


// ─── added with upstream's os.Root, Unix-socket and pprof surface ──────
//
// Linux gained these while the port was on a branch. Same signatures as
// `syscall_linux.rs`, each an abort naming the milestone that owns it:
// the fd-relative file calls are the M2 file surface, the raw socket
// calls are M9, and `Setitimer` drives pprof's SIGPROF, which is M6.

#[allow(non_snake_case)]
pub fn __openat_raw(dirfd: i32, path: *const u8, flags: i32, mode: i32) -> i32 {
    unsafe { sys::sys_openat(dirfd, path, flags, mode) as i32 }
}

#[allow(non_snake_case)]
pub fn Mkdirat(dirfd: i32, path: *const u8, mode: u32) -> i32 {
    unsafe { sys::sys_mkdirat(dirfd, path, mode as u16) as i32 }
}

#[allow(non_snake_case)]
pub fn Unlinkat(dirfd: i32, path: *const u8, flags: i32) -> i32 {
    unsafe { sys::sys_unlinkat(dirfd, path, flags) as i32 }
}

#[allow(non_snake_case)]
pub fn Fstatat(dirfd: i32, path: *const u8, out: &mut Stat_t, flags: i32) -> i32 {
    unsafe { sys::sys_fstatat(dirfd, path, out as *mut Stat_t as *mut u8, flags) as i32 }
}

#[allow(non_snake_case)]
pub fn Renameat(olddirfd: i32, oldpath: *const u8, newdirfd: i32, newpath: *const u8) -> i32 {
    unsafe { sys::sys_renameat(olddirfd, oldpath, newdirfd, newpath) as i32 }
}

#[allow(non_snake_case)]
pub fn Linkat(
    olddirfd: i32,
    oldpath: *const u8,
    newdirfd: i32,
    newpath: *const u8,
    flags: i32,
) -> i32 {
    unsafe { sys::sys_linkat(olddirfd, oldpath, newdirfd, newpath, flags) as i32 }
}

#[allow(non_snake_case)]
pub fn Symlinkat(target: *const u8, newdirfd: i32, linkpath: *const u8) -> i32 {
    unsafe { sys::sys_symlinkat(target, newdirfd, linkpath) as i32 }
}

#[allow(non_snake_case)]
pub fn Fchdir(fd: i32) -> i32 {
    unsafe { sys::sys_fchdir(fd) as i32 }
}

#[allow(non_snake_case)]
pub fn Fchown(fd: i32, uid: u32, gid: u32) -> i32 {
    unsafe { sys::sys_fchown(fd, uid, gid) as i32 }
}

#[allow(non_snake_case)]
pub fn Fchmodat(dirfd: i32, path: *const u8, mode: u32, flags: i32) -> i32 {
    unsafe { sys::sys_fchmodat(dirfd, path, mode as u16, flags) as i32 }
}

#[allow(non_snake_case)]
pub fn Fchownat(dirfd: i32, path: *const u8, uid: u32, gid: u32, flags: i32) -> i32 {
    unsafe { sys::sys_fchownat(dirfd, path, uid, gid, flags) as i32 }
}

#[allow(non_snake_case)]
pub fn Readlinkat(dirfd: i32, path: *const u8, buf: *mut u8, bufsiz: usize) -> isize {
    unsafe { sys::sys_readlinkat(dirfd, path, buf, bufsiz) }
}

#[allow(non_snake_case)]
pub fn __bind_raw(fd: i32, addr: *const u8, addrlen: u32) -> i32 {
    unsafe { sys::sys_bind(fd, addr, addrlen) as i32 }
}

#[allow(non_snake_case)]
pub fn __connect_raw(fd: i32, addr: *const u8, addrlen: u32) -> i32 {
    unsafe { sys::sys_connect(fd, addr, addrlen) as i32 }
}

#[allow(non_snake_case)]
pub fn __accept4_raw(fd: i32, addr: *mut u8, addrlen: *mut u32, flags: i32) -> i32 {
    accept_with_flags(fd, addr, addrlen, flags)
}

#[allow(non_snake_case)]
pub fn Setitimer(which: i32, new: *const Itimerval, old: *mut Itimerval) -> i32 {
    unsafe { sys::sys_setitimer(which, new as *const u8, old as *mut u8) as i32 }
}

// ─── M2: the file surface, continued ───────────────────────────────────

// NUL-terminate a goish string for libSystem.
fn __c_path(path: crate::string) -> alloc::vec::Vec<u8> {
    let mut v = alloc::vec::Vec::with_capacity(path.as_bytes().len() + 1);
    v.extend_from_slice(path.as_bytes());
    v.push(0);
    v
}

/// Go's `syscall.Openat`: `(fd, nil)`, `(-1, errno)`, or `(0, EINVAL)`
/// for an embedded NUL before any call — the Linux wrapper's contract.
#[allow(non_snake_case)]
pub fn Openat<P: Into<crate::string>>(
    dirfd: crate::int,
    path: P,
    flags: crate::int,
    mode: u32,
) -> (crate::int, crate::error) {
    let path = path.into();
    if path.as_bytes().contains(&0) {
        return (0, EINVAL.into());
    }
    let path = __c_path(path);
    let rc = unsafe { sys::sys_openat(dirfd as i32, path.as_ptr(), flags as i32, mode as i32) };
    if rc < 0 {
        return (-1, Errno(-(rc as i32)).into());
    }
    (rc as crate::int, crate::errors::nil)
}

/// `umask(2)` — set the file-creation mask, returning the previous one.
#[allow(non_snake_case)]
pub fn Umask(mask: crate::int) -> crate::int {
    unsafe { sys::sys_umask(mask as u16) as crate::int }
}

/// File-type bits for `Mknod`'s mode argument, typed `i32` as on Linux.
pub const S_IFIFO: i32 = 0o010000;
pub const S_IFSOCK: i32 = 0o140000;

/// `mknod(path, mode, dev)`. A FIFO goes through `mkfifo`: Darwin's
/// `mknod(2)` is superuser-only for every node type, including the one
/// an unprivileged process may make on Linux.
#[allow(non_snake_case)]
pub fn Mknod(path: *const u8, mode: i32, dev: u64) -> i32 {
    unsafe {
        if mode & 0o170000 == S_IFIFO {
            sys::sys_mkfifo(path, (mode & 0o7777) as u16) as i32
        } else {
            sys::sys_mknod(path, mode as u16, dev as i32) as i32
        }
    }
}

/// `fsync(2)`. Returns 0 or `-errno`.
#[allow(non_snake_case)]
pub fn Fsync(fd: i32) -> i32 {
    unsafe { sys::sys_fsync(fd) as i32 }
}

/// Read directory entries into `buf` as **`linux_dirent64` records**,
/// which is what `os` parses on every target: `d_ino` u64, `d_off`
/// i64, `d_reclen` u16, `d_type` u8, then the NUL-terminated name,
/// each record padded to 8 bytes. Returns the bytes filled, 0 at the
/// end, or `-errno`.
///
/// Darwin's records carry a `d_namlen` Linux's do not and pad to 4, so
/// a Linux record is at most 8/7 the size of the Darwin one it came
/// from. Reading at most three quarters of `buf` from the kernel
/// therefore always fits after translation, and nothing read is ever
/// dropped — which matters, because the directory offset has already
/// moved past it.
fn getdents64(fd: i32, buf: *mut u8, buflen: usize) -> i64 {
    // The kernel wants room for at least one full `struct dirent`.
    const DIRENT_MAX: usize = 1048;
    let want = (buflen / 4 * 3).max(DIRENT_MAX);
    let mut tmp: alloc::vec::Vec<u8> = alloc::vec![0u8; want];
    let mut base: i64 = 0;
    let n = unsafe { sys::sys_getdirentries64(fd, tmp.as_mut_ptr(), want, &mut base) };
    if n <= 0 {
        return n as i64;
    }
    let n = n as usize;
    let (mut i, mut o) = (0usize, 0usize);
    while i + 21 <= n {
        let rec = &tmp[i..];
        let reclen = u16::from_ne_bytes([rec[16], rec[17]]) as usize;
        let namlen = u16::from_ne_bytes([rec[18], rec[19]]) as usize;
        if reclen == 0 {
            break;
        }
        let out = (19 + namlen + 1 + 7) & !7;
        if o + out > buflen {
            // Only reachable if `buflen` is below one Darwin dirent;
            // report what fits rather than overrun the caller.
            return if o == 0 { -(EINVAL.0 as i64) } else { o as i64 };
        }
        unsafe {
            let d = buf.add(o);
            core::ptr::write_bytes(d, 0, out);
            core::ptr::copy_nonoverlapping(rec.as_ptr(), d, 8); // d_ino
            core::ptr::copy_nonoverlapping(rec.as_ptr().add(8), d.add(8), 8); // d_off ← d_seekoff
            core::ptr::copy_nonoverlapping((out as u16).to_ne_bytes().as_ptr(), d.add(16), 2);
            *d.add(18) = rec[20]; // d_type — the DT_* values agree
            core::ptr::copy_nonoverlapping(rec.as_ptr().add(21), d.add(19), namlen);
        }
        o += out;
        i += reclen;
    }
    o as i64
}

// ─── M9: sockets and the epoll surface over kqueue ─────────────────────

/// Set `O_NONBLOCK` and/or `FD_CLOEXEC` on `fd` — what Linux's
/// `SOCK_NONBLOCK`/`SOCK_CLOEXEC` type bits do atomically. Also turns on
/// `SO_NOSIGPIPE` for sockets: Darwin has no `MSG_NOSIGNAL`, and a
/// write to a reset peer must come back as `EPIPE`, not a signal.
fn apply_sock_flags(fd: i32, flags: i32) -> i32 {
    unsafe {
        if flags & SOCK_CLOEXEC != 0 {
            let r = sys::sys_fcntl(fd, F_SETFD, FD_CLOEXEC as isize);
            if r < 0 {
                return r as i32;
            }
        }
        if flags & SOCK_NONBLOCK != 0 {
            let fl = sys::sys_fcntl(fd, F_GETFL, 0);
            if fl < 0 {
                return fl as i32;
            }
            let r = sys::sys_fcntl(fd, F_SETFL, fl | O_NONBLOCK as isize);
            if r < 0 {
                return r as i32;
            }
        }
        let one: i32 = 1;
        let _ = sys::sys_setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one as *const i32 as *const u8, 4);
    }
    0
}

/// `socket(2)` honouring Linux's `SOCK_NONBLOCK | SOCK_CLOEXEC` type
/// bits, which Darwin does not have: the socket is made plain and the
/// bits applied after — Go's darwin `sysSocket` (`net/sys_cloexec.go`).
fn socket_with_flags(domain: i32, ty: i32, proto: i32) -> i32 {
    let flags = ty & (SOCK_NONBLOCK | SOCK_CLOEXEC);
    let fd = unsafe { sys::sys_socket(domain, ty & !(SOCK_NONBLOCK | SOCK_CLOEXEC), proto) } as i32;
    if fd < 0 {
        return fd;
    }
    let r = apply_sock_flags(fd, flags);
    if r < 0 {
        unsafe { sys::sys_close(fd) };
        return r;
    }
    fd
}

/// `accept4(2)` as `accept` plus the flags — Go's darwin `accept`
/// (`internal/poll/sys_cloexec.go`). Accepted sockets do not inherit
/// `O_NONBLOCK` on Darwin either, so it is set explicitly.
fn accept_with_flags(fd: i32, addr: *mut u8, len: *mut u32, flags: i32) -> i32 {
    let nfd = unsafe { sys::sys_accept(fd, addr, len) } as i32;
    if nfd < 0 {
        return nfd;
    }
    let r = apply_sock_flags(nfd, flags);
    if r < 0 {
        unsafe { sys::sys_close(nfd) };
        return r;
    }
    nfd
}

/// `getsockname(2)` into a caller buffer. 0 or `-errno`.
#[allow(non_snake_case)]
pub fn Getsockname(fd: i32, addr: *mut u8, addrlen: *mut u32) -> i32 {
    unsafe { sys::sys_getsockname(fd, addr, addrlen) as i32 }
}

/// `getpeername(2)` into a caller buffer. 0 or `-errno`.
#[allow(non_snake_case)]
pub fn Getpeername(fd: i32, addr: *mut u8, addrlen: *mut u32) -> i32 {
    unsafe { sys::sys_getpeername(fd, addr, addrlen) as i32 }
}

/// `sendto(2)`; `addr` may be null for a connected socket. Returns the
/// byte count or `-errno`.
#[allow(non_snake_case)]
pub fn Sendto(fd: i32, buf: *const u8, len: usize, flags: i32, addr: *const u8, addrlen: u32) -> isize {
    unsafe { sys::sys_sendto(fd, buf, len, flags, addr, addrlen) }
}

/// `recvfrom(2)` also reporting the sender. Returns the byte count or
/// `-errno`.
#[allow(non_snake_case)]
pub fn RecvfromAddr(fd: i32, buf: *mut u8, len: usize, flags: i32, addr: *mut u8, addrlen: *mut u32) -> isize {
    unsafe { sys::sys_recvfrom(fd, buf, len, flags, addr, addrlen) }
}

/// `socketpair(2)`, honouring the same type bits as `Socket`.
#[allow(non_snake_case)]
pub fn Socketpair(domain: i32, ty: i32, proto: i32, sv: &mut [i32; 2]) -> i32 {
    let flags = ty & (SOCK_NONBLOCK | SOCK_CLOEXEC);
    let r = unsafe {
        sys::sys_socketpair(domain, ty & !(SOCK_NONBLOCK | SOCK_CLOEXEC), proto, sv.as_mut_ptr())
    } as i32;
    if r < 0 {
        return r;
    }
    for &fd in sv.iter() {
        let e = apply_sock_flags(fd, flags);
        if e < 0 {
            unsafe {
                sys::sys_close(sv[0]);
                sys::sys_close(sv[1]);
            }
            return e;
        }
    }
    0
}

// The epoll surface, over kqueue. `runtime::netpoll` is written to
// epoll's shape — register once, edge-triggered, wait for a batch —
// and kqueue expresses the same thing with one filter per direction,
// so the translation is local and the poller above it is shared:
//
//   EPOLLIN / EPOLLOUT   → EVFILT_READ / EVFILT_WRITE, one kevent each
//   EPOLLET              → EV_CLEAR (edge-triggered)
//   EPOLLONESHOT         → EV_ONESHOT
//   `data`               ↔ `udata`, returned untouched
//   EV_EOF on read       → EPOLLIN | EPOLLRDHUP | EPOLLHUP
//   EV_EOF on write      → EPOLLOUT | EPOLLHUP
//   EV_ERROR             → EPOLLERR
//
// Go's darwin netpoller registers exactly this pair with EV_CLEAR
// (`runtime/netpoll_kqueue.go`, `netpollopen`), and wakes writers as
// well as readers on a read-side EOF, which is what folding EPOLLHUP
// into the read event does here. A kqueue event for the same fd in
// each direction arrives as two `EpollEvent`s rather than one; the
// poller handles each on its own.
//
// The netpoller's break is `EVFILT_USER` (see `NetpollWakeAdd`), which
// Go uses on darwin in place of the eventfd (`netpoll_kqueue_event.go`).

fn epoll_create1(flags: i32) -> i32 {
    let kq = unsafe { sys::sys_kqueue() } as i32;
    if kq >= 0 && flags & O_CLOEXEC != 0 {
        unsafe { sys::sys_fcntl(kq, F_SETFD, FD_CLOEXEC as isize) };
    }
    kq
}

fn kev(fd: i32, filter: i16, flags: u16, udata: u64) -> sys::Kevent {
    sys::Kevent { ident: fd as usize, filter, flags, fflags: 0, data: 0, udata: udata as usize }
}

fn epoll_ctl(epfd: i32, op: i32, fd: i32, event: *mut EpollEvent) -> i32 {
    let (want, data) = if event.is_null() {
        (0, 0)
    } else {
        unsafe { ((*event).events, (*event).data) }
    };
    let mut fl = 0u16;
    if want & EPOLLET != 0 {
        fl |= sys::EV_CLEAR;
    }
    if want & EPOLLONESHOT != 0 {
        fl |= sys::EV_ONESHOT;
    }
    // EV_RECEIPT reports each change's own result rather than draining
    // pending events, so a DEL of a filter that was never added comes
    // back as a per-change ENOENT the caller can ignore.
    let mut ch: [sys::Kevent; 2] = Default::default();
    match op {
        EPOLL_CTL_ADD | EPOLL_CTL_MOD => {
            for (i, (bit, filt)) in [(EPOLLIN, sys::EVFILT_READ), (EPOLLOUT, sys::EVFILT_WRITE)]
                .into_iter()
                .enumerate()
            {
                ch[i] = if want & bit != 0 {
                    kev(fd, filt, sys::EV_ADD | sys::EV_RECEIPT | fl, data)
                } else {
                    kev(fd, filt, sys::EV_DELETE | sys::EV_RECEIPT, 0)
                };
            }
        }
        EPOLL_CTL_DEL => {
            ch[0] = kev(fd, sys::EVFILT_READ, sys::EV_DELETE | sys::EV_RECEIPT, 0);
            ch[1] = kev(fd, sys::EVFILT_WRITE, sys::EV_DELETE | sys::EV_RECEIPT, 0);
        }
        _ => return -(EINVAL.0),
    }
    let mut out: [sys::Kevent; 2] = Default::default();
    let n = unsafe { sys::sys_kevent(epfd, &ch, &mut out, Some(0)) };
    if n < 0 {
        return n as i32;
    }
    for r in &out[..n as usize] {
        // With EV_RECEIPT every entry carries EV_ERROR; `data` is the
        // errno, 0 on success.
        let e = r.data as i32;
        if e == 0 {
            continue;
        }
        let deleting = op == EPOLL_CTL_DEL
            || (r.filter == sys::EVFILT_READ && want & EPOLLIN == 0)
            || (r.filter == sys::EVFILT_WRITE && want & EPOLLOUT == 0);
        if deleting && e == ENOENT.0 {
            continue;
        }
        return -e;
    }
    0
}

fn epoll_pwait(epfd: i32, events: *mut EpollEvent, maxevents: i32, timeout_ms: i32) -> i32 {
    const BATCH: usize = 128;
    let max = (maxevents.max(0) as usize).min(BATCH);
    let mut kevs: [sys::Kevent; BATCH] = [sys::Kevent::default(); BATCH];
    let timeout = if timeout_ms < 0 { None } else { Some(timeout_ms as i64 * 1_000_000) };
    let n = unsafe { sys::sys_kevent(epfd, &[], &mut kevs[..max], timeout) };
    if n < 0 {
        return n as i32;
    }
    for (i, k) in kevs[..n as usize].iter().enumerate() {
        let mut bits = match k.filter {
            sys::EVFILT_READ => {
                if k.flags & sys::EV_EOF != 0 {
                    EPOLLIN | EPOLLRDHUP | EPOLLHUP
                } else {
                    EPOLLIN
                }
            }
            sys::EVFILT_WRITE => {
                if k.flags & sys::EV_EOF != 0 {
                    EPOLLOUT | EPOLLHUP
                } else {
                    EPOLLOUT
                }
            }
            // The netpoller's break, reported as readable.
            _ => EPOLLIN,
        };
        if k.flags & sys::EV_ERROR != 0 {
            bits |= EPOLLERR;
        }
        unsafe {
            *events.add(i) = EpollEvent { events: bits, data: k.udata as u64 };
        }
    }
    n as i32
}

/// The netpoller's break: an `EVFILT_USER` event on `kq`, reported with
/// `data` as its `EpollEvent.data`. `EV_CLEAR` so one trigger is one
/// wakeup — Go's `addWakeupEvent` (`runtime/netpoll_kqueue_event.go`).
#[allow(non_snake_case)]
pub fn NetpollWakeAdd(kq: i32, data: u64) -> i32 {
    let ev = sys::Kevent {
        ident: NETPOLL_WAKE_IDENT,
        filter: sys::EVFILT_USER,
        flags: sys::EV_ADD | sys::EV_CLEAR,
        fflags: 0,
        data: 0,
        udata: data as usize,
    };
    unsafe { sys::sys_kevent(kq, &[ev], &mut [], Some(0)) as i32 }
}

/// Trigger the break registered by `NetpollWakeAdd` — Go's
/// `wakeNetpoll`. Retries `EINTR`, as Go does.
#[allow(non_snake_case)]
pub fn NetpollWakeTrigger(kq: i32) -> i32 {
    let ev = sys::Kevent {
        ident: NETPOLL_WAKE_IDENT,
        filter: sys::EVFILT_USER,
        flags: 0,
        fflags: sys::NOTE_TRIGGER,
        data: 0,
        udata: 0,
    };
    loop {
        let r = unsafe { sys::sys_kevent(kq, &[ev], &mut [], Some(0)) } as i32;
        if r != -EINTR.0 {
            return r;
        }
    }
}

/// Go's `kqIdent`: any value works, one that stands out in a trace is
/// better.
const NETPOLL_WAKE_IDENT: usize = 0xee1eb9f4;

// ─── M8: thread-directed signals ───────────────────────────────────────

/// `pthread_kill(thread, sig)` — Darwin's way to signal one thread
/// (Go's darwin `signalM`, runtime/os_darwin.go). `Tgkill` has no
/// equivalent here: a Mach thread id cannot be signalled, a `pthread_t`
/// can. Returns 0 or `-errno`.
#[allow(non_snake_case)]
pub fn PthreadKill(thread: usize, sig: i32) -> isize {
    unsafe { sys::sys_pthread_kill(thread, sig) }
}

// ─── os/exec: Fork, Execve, Wait4, Pipe2, Dup3 ─────────────────────────
//
// Go's darwin process creation is `syscall/exec_libc2.go`: libc `fork`,
// then only libc calls known to be safe in the child (`dup2`, `fcntl`,
// `chdir`, `execve`, `write`, `exit`) until the exec. goish's child side
// lives in `os::exec::Cmd::Start` and is shared with Linux; what differs
// per platform is below, behind the same names and signatures that
// `syscall_linux.rs` exports.
//
// Why fork+exec and not `posix_spawn`: the shared child path does a
// `chdir` for `Cmd.Dir`, rewires fds 0-2 from pipes, and reports the
// exec errno back through a CLOEXEC pipe. `posix_spawn` expresses the
// first only through the non-portable
// `posix_spawn_file_actions_addchdir_np`, and the last not at all — it
// returns the errno itself, so the error pipe would become a second,
// Darwin-only error path. Keeping Go's shape keeps one child path for
// both targets.

/// Go's `syscall.ForkLock`, reduced to what Darwin needs it for.
///
/// Linux creates every fd with its close-on-exec bit already set
/// (`pipe2`, `dup3`, `SOCK_CLOEXEC`). Darwin has no `pipe2`, so `Pipe2`
/// below makes the pipe and *then* sets `FD_CLOEXEC`. A fork on another
/// thread in that window hands the child a pipe end it never closes,
/// and whoever reads the other end waits for an EOF that arrives only
/// when that unrelated child exits. Go closes the window with this
/// lock: fd creation that is not atomic takes it shared (`os.Pipe`
/// calls `syscall.Pipe` under `ForkLock.RLock`), and `forkExec` takes
/// it exclusive across the fork (`acquireForkLock`,
/// `syscall/forkpipe.go:24-26`).
///
/// A spin lock rather than a parking mutex, because both critical
/// sections are a handful of syscalls that never block, and every
/// holder runs under `acquirem` so it cannot be preempted off its M
/// while a waiter spins — the GOMAXPROCS=1 deadlock a parking-free
/// lock would otherwise have. Bit 31 is the writer; the low bits count
/// readers.
static FORK_LOCK: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
const FORK_LOCK_WRITER: u32 = 1 << 31;

fn fork_lock_rlock() {
    use core::sync::atomic::Ordering;
    crate::runtime::sched::acquirem();
    loop {
        let v = FORK_LOCK.load(Ordering::Relaxed);
        if v & FORK_LOCK_WRITER == 0
            && FORK_LOCK
                .compare_exchange_weak(v, v + 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
        {
            return;
        }
        core::hint::spin_loop();
    }
}

fn fork_lock_runlock() {
    FORK_LOCK.fetch_sub(1, core::sync::atomic::Ordering::Release);
    crate::runtime::sched::releasem();
}

fn fork_lock_lock() {
    use core::sync::atomic::Ordering;
    crate::runtime::sched::acquirem();
    // Claim the writer bit first so no new reader gets in, then wait
    // for the ones already inside to leave.
    while FORK_LOCK.fetch_or(FORK_LOCK_WRITER, Ordering::Acquire) & FORK_LOCK_WRITER != 0 {
        core::hint::spin_loop();
    }
    while FORK_LOCK.load(Ordering::Acquire) != FORK_LOCK_WRITER {
        core::hint::spin_loop();
    }
}

fn fork_lock_unlock() {
    FORK_LOCK.fetch_and(!FORK_LOCK_WRITER, core::sync::atomic::Ordering::Release);
    crate::runtime::sched::releasem();
}

/// `<sys/signal.h>`: `SIG_SETMASK` is 3, `SIG_DFL`/`SIG_IGN` are the
/// handler values 0 and 1, and `NSIG` is 32 (signals 1-31).
const SIG_SETMASK_DARWIN: i32 = 3;
const SIG_DFL_DARWIN: usize = 0;
const SIG_IGN_DARWIN: usize = 1;
const NSIG_DARWIN: i32 = 32;

/// `fork(2)` through libSystem — 0 in the child, the child's pid in the
/// parent, `-errno` on failure.
///
/// Go: `syscall/exec_libc2.go:82-95` (the fork) and `:147-149` (the
/// child's `runtime_AfterForkInChild`), with the two runtime hooks from
/// `runtime/proc.go`:
///
///  * `syscall_runtime_BeforeFork` (`proc.go:5165-5180`) blocks every
///    signal across the fork "so that the child does not run a signal
///    handler before exec if a signal is sent to the process group"
///    (go.dev/issue/18600). goish's handlers — SIGURG preemption, the
///    SIGSEGV reporter, `os/signal` — all assume a live scheduler, and
///    the child has one thread and no scheduler.
///  * `syscall_runtime_AfterForkInChild` (`proc.go:5228-5245`) then,
///    in the child, puts every caught signal back to `SIG_DFL`
///    (`clearSignalHandlers`, `runtime/signal_unix.go:268-276`) and only
///    then restores the mask. The order matters: exec preserves the
///    mask, so it must be restored, and restoring it with goish's
///    handlers still installed would let a pending signal run one.
///    Ignored signals stay ignored, as in Go — `SIG_IGN` survives exec.
///
/// Both halves live here rather than in `os::exec` so the child path
/// that follows is the same code on both targets, and the ordering
/// matches Go's: signals are clean before the child's `dup2`/`chdir`.
///
/// Every call in the child is async-signal-safe (`sigaction`,
/// `pthread_sigmask`), nothing allocates, and `FORK_LOCK` is released
/// by one atomic RMW plus `releasem`'s TLS-relative decrement.
#[allow(non_snake_case)]
pub fn Fork() -> i32 {
    unsafe {
        let all: u32 = !0;
        let mut old: u32 = 0;
        fork_lock_lock();
        sys::sys_pthread_sigmask(SIG_SETMASK_DARWIN, &all, &mut old);
        let pid = sys::sys_fork() as i32;
        if pid == 0 {
            let mut sig = 1;
            while sig < NSIG_DARWIN {
                let mut cur = sys::BsdSigaction::default();
                if sys::sys_sigaction(sig, core::ptr::null(), &mut cur) == 0
                    && cur.handler != SIG_DFL_DARWIN
                    && cur.handler != SIG_IGN_DARWIN
                {
                    // SIG_DFL, empty mask, no flags.
                    let dfl = sys::BsdSigaction::default();
                    sys::sys_sigaction(sig, &dfl, core::ptr::null_mut());
                }
                sig += 1;
            }
        }
        sys::sys_pthread_sigmask(SIG_SETMASK_DARWIN, &old, core::ptr::null_mut());
        fork_lock_unlock();
        pid
    }
}

/// `execve(2)` — returns only on failure, with `-errno`.
/// Go: `exec_libc2.go:282-286`.
#[allow(non_snake_case)]
pub fn Execve(path: *const u8, argv: *const *const u8, envp: *const *const u8) -> i32 {
    unsafe { sys::sys_execve(path, argv, envp) as i32 }
}

/// `wait4(2)` — the reaped pid, or `-errno`.
///
/// Darwin's status word has Linux's layout for the exited, signalled
/// and stopped cases — low 7 bits the signal, `0x7f` stopped, `0x80`
/// core, exit code in bits 8-15 (Go: `syscall/syscall_bsd.go`,
/// `WaitStatus`). Its `struct rusage` is the same 144 bytes, except
/// that each `timeval` has a 32-bit `tv_usec` plus padding (Go:
/// `syscall/ztypes_darwin_arm64.go:26-30`), which
/// `os::exec_posix::timeval_to_duration` accounts for.
///
/// No EINTR loop: every handler goish installs that can interrupt a
/// blocked thread carries `SA_RESTART`.
#[allow(non_snake_case)]
pub fn Wait4(pid: i32, status: *mut i32, options: i32, rusage: *mut u8) -> i32 {
    unsafe { sys::sys_wait4(pid, status, options, rusage) as i32 }
}

/// `pipe2(2)`, which Darwin does not have: `pipe(2)`, then the flags
/// one `fcntl` at a time — Go's `forkExecPipe`
/// (`syscall/forkpipe.go:11-22`) for `O_CLOEXEC`, plus `F_SETFL` for
/// `O_NONBLOCK`. The flag values are Darwin's (`O_CLOEXEC` is
/// `0x1000000` here), so a caller passing `syscall::O_CLOEXEC` by name
/// gets the right bit on both targets.
///
/// Held under `FORK_LOCK` shared, so no fork observes the pipe between
/// its creation and its close-on-exec bit. On failure both ends are
/// closed, `-errno` is returned and `pipefd` is left untouched.
#[allow(non_snake_case)]
pub fn Pipe2(pipefd: &mut [i32; 2], flags: i32) -> i32 {
    let mut p = [-1i32; 2];
    fork_lock_rlock();
    let r = unsafe { pipe2_locked(&mut p, flags) };
    fork_lock_runlock();
    if r == 0 {
        *pipefd = p;
    }
    r
}

unsafe fn pipe2_locked(p: &mut [i32; 2], flags: i32) -> i32 {
    let r = sys::sys_pipe(p.as_mut_ptr());
    if r < 0 {
        return r as i32;
    }
    for &fd in p.iter() {
        let mut r: isize = 0;
        if flags & O_CLOEXEC != 0 {
            r = sys::sys_fcntl(fd, F_SETFD, FD_CLOEXEC as isize);
        }
        if r >= 0 && flags & O_NONBLOCK != 0 {
            r = sys::sys_fcntl(fd, F_GETFL, 0);
            if r >= 0 {
                r = sys::sys_fcntl(fd, F_SETFL, r | O_NONBLOCK as isize);
            }
        }
        if r < 0 {
            sys::sys_close(p[0]);
            sys::sys_close(p[1]);
            return r as i32;
        }
    }
    0
}

/// `dup3(2)`, which Darwin does not have: `dup2(2)`, plus `FD_CLOEXEC`
/// when `flags` asks for it. The fd `dup2` creates is not
/// close-on-exec, "which is exactly what we want" for the child's stdio
/// (Go: `exec_libc2.go:245-247`), so `flags == 0` is a plain `dup2` —
/// the only form the child path uses, and async-signal-safe.
///
/// One difference kept visible rather than papered over: Linux's
/// `dup3(fd, fd, …)` is `EINVAL`, while `dup2(fd, fd)` succeeds and
/// leaves the flags alone (`exec_libc2.go:236-243`). No caller passes
/// equal fds.
#[allow(non_snake_case)]
pub fn Dup3(oldfd: i32, newfd: i32, flags: i32) -> i32 {
    if flags & O_CLOEXEC == 0 {
        return unsafe { sys::sys_dup2(oldfd, newfd) as i32 };
    }
    fork_lock_rlock();
    let r = unsafe {
        let r = sys::sys_dup2(oldfd, newfd);
        if r >= 0 {
            let s = sys::sys_fcntl(newfd, F_SETFD, FD_CLOEXEC as isize);
            if s < 0 {
                sys::sys_close(newfd);
                s
            } else {
                r
            }
        } else {
            r
        }
    } as i32;
    fork_lock_runlock();
    r
}

/// Leave a forked child that could not exec: `_exit(2)`, not the
/// `exit(3)` behind `Exit`. See `sys::sys_exit_child` for why this
/// departs from Go's `libc_exit` (`exec_libc2.go:291-293`).
#[allow(non_snake_case)]
pub fn ForkExit(code: i32) -> ! {
    unsafe { sys::sys_exit_child(code) }
}
