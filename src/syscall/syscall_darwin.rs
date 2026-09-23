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
// `os/exec` is marked as such rather than with a number — it is out of
// scope for the whole ladder (see the plan's "Explicitly out of scope";
// `fork` + exec is translatable, `pipe2` is not, and fork-in-a-threaded-
// process is stricter here).

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
#[allow(non_snake_case, unused_variables)]
pub fn Ioctl(fd: i32, req: usize, arg: usize) -> isize {
    todo("Ioctl", "M6")
}

#[allow(non_snake_case, unused_variables)]
pub fn Open(path: *const u8, flags: i32, mode: i32) -> i32 {
    todo("Open", "M2")
}

#[allow(non_snake_case, unused_variables)]
pub fn Close(fd: i32) -> i32 {
    todo("Close", "M2")
}

#[allow(non_snake_case, unused_variables)]
pub fn Fork() -> i32 {
    todo("Fork", "os/exec")
}

#[allow(non_snake_case, unused_variables)]
pub fn Execve(path: *const u8, argv: *const *const u8, envp: *const *const u8) -> i32 {
    todo("Execve", "os/exec")
}

#[allow(non_snake_case, unused_variables)]
pub fn Wait4(pid: i32, status: *mut i32, options: i32, rusage: *mut u8) -> i32 {
    todo("Wait4", "os/exec")
}

#[allow(non_snake_case, unused_variables)]
pub fn Dup3(oldfd: i32, newfd: i32, flags: i32) -> i32 {
    todo("Dup3", "os/exec")
}

#[allow(non_snake_case, unused_variables)]
pub fn Fstat(fd: i32, out: &mut Stat_t) -> i32 {
    todo("Fstat", "M2")
}

#[allow(non_snake_case, unused_variables)]
pub fn Stat(path: *const u8, out: &mut Stat_t) -> i32 {
    todo("Stat", "M2")
}

#[allow(non_snake_case, unused_variables)]
pub fn Lstat(path: *const u8, out: &mut Stat_t) -> i32 {
    todo("Lstat", "M2")
}

#[allow(non_snake_case, unused_variables)]
pub fn Lseek(fd: i32, offset: i64, whence: i32) -> i64 {
    todo("Lseek", "M2")
}

#[allow(non_snake_case, unused_variables)]
pub fn Pread64(fd: i32, buf: *mut u8, count: usize, offset: i64) -> isize {
    todo("Pread64", "M2")
}

#[allow(non_snake_case, unused_variables)]
pub fn Pwrite64(fd: i32, buf: *const u8, count: usize, offset: i64) -> isize {
    todo("Pwrite64", "M2")
}

#[allow(non_snake_case, unused_variables)]
pub fn Ftruncate(fd: i32, length: i64) -> i32 {
    todo("Ftruncate", "M2")
}

#[allow(non_snake_case, unused_variables)]
pub fn Flock(fd: crate::types::int, operation: crate::types::int) -> crate::errors::error {
    todo("Flock", "M2")
}

#[allow(non_snake_case, unused_variables)]
pub fn Mkdir(path: *const u8, mode: u32) -> i32 {
    todo("Mkdir", "M2")
}

#[allow(non_snake_case, unused_variables)]
pub fn Unlink(path: *const u8) -> i32 {
    todo("Unlink", "M2")
}

#[allow(non_snake_case, unused_variables)]
pub fn Rmdir(path: *const u8) -> i32 {
    todo("Rmdir", "M2")
}

#[allow(non_snake_case, unused_variables)]
pub fn Getcwd(buf: *mut u8, size: usize) -> isize {
    todo("Getcwd", "M2")
}

#[allow(non_snake_case, unused_variables)]
pub fn Chdir(path: *const u8) -> i32 {
    todo("Chdir", "M2")
}

#[allow(non_snake_case, unused_variables)]
pub fn Chmod(path: *const u8, mode: u32) -> i32 {
    todo("Chmod", "M2")
}

#[allow(non_snake_case, unused_variables)]
pub fn Fchmod(fd: i32, mode: u32) -> i32 {
    todo("Fchmod", "M2")
}

#[allow(non_snake_case, unused_variables)]
pub fn Symlink(oldname: *const u8, newname: *const u8) -> i32 {
    todo("Symlink", "M2")
}

#[allow(non_snake_case, unused_variables)]
pub fn Readlink(path: *const u8, buf: *mut u8, bufsiz: usize) -> isize {
    todo("Readlink", "M2")
}

#[allow(non_snake_case, unused_variables)]
pub fn Utimensat(dirfd: i32, path: *const u8, times: *const Timespec, flags: i32) -> i32 {
    todo("Utimensat", "M2")
}

#[allow(non_snake_case, unused_variables)]
pub fn Rename(oldpath: *const u8, newpath: *const u8) -> i32 {
    todo("Rename", "M2")
}

#[allow(non_snake_case, unused_variables)]
pub fn Link(oldpath: *const u8, newpath: *const u8) -> i32 {
    todo("Link", "M2")
}

#[allow(non_snake_case, unused_variables)]
pub fn Truncate(path: *const u8, length: i64) -> i32 {
    todo("Truncate", "M2")
}

#[allow(non_snake_case, unused_variables)]
pub fn Pipe2(pipefd: &mut [i32; 2], flags: i32) -> i32 {
    todo("Pipe2", "os/exec")
}

#[allow(non_snake_case, unused_variables)]
pub fn Chown(path: *const u8, uid: i32, gid: i32) -> i32 {
    todo("Chown", "M2")
}

#[allow(non_snake_case, unused_variables)]
pub fn Lchown(path: *const u8, uid: i32, gid: i32) -> i32 {
    todo("Lchown", "M2")
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

#[allow(non_snake_case, unused_variables)]
pub fn Getdents64(fd: i32, buf: *mut u8, buflen: usize) -> i64 {
    todo("Getdents64", "M2")
}

#[allow(non_snake_case, unused_variables)]
pub fn Recvfrom(fd: i32, buf: *mut u8, len: usize, flags: i32) -> isize {
    todo("Recvfrom", "M9")
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

#[allow(non_snake_case, unused_variables)]
pub unsafe fn RtSigaction(
    sig: i32,
    new: *const Sigaction,
    old: *mut Sigaction,
) -> isize {
    todo("RtSigaction", "M6")
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

#[allow(non_snake_case, unused_variables)]
pub fn SchedYield() -> isize {
    todo("SchedYield", "M5")
}

#[allow(non_snake_case, unused_variables)]
pub fn Futex(
    addr: *const u32,
    op: i32,
    val: u32,
    ts: *const Timespec,
) -> isize {
    todo("Futex", "M7")
}

#[allow(non_snake_case, unused_variables)]
pub fn SchedGetaffinity(pid: i32, cpusetsize: usize, mask: *mut u8) -> isize {
    todo("SchedGetaffinity", "M3")
}

#[allow(non_snake_case, unused_variables)]
pub fn ExitThread(code: i32) -> ! {
    todo("ExitThread", "M4")
}

#[allow(non_snake_case, unused_variables)]
pub fn Socket(domain: i32, type_: i32, protocol: i32) -> i32 {
    todo("Socket", "M9")
}

#[allow(non_snake_case, unused_variables)]
pub fn Bind(fd: i32, addr: *const SockaddrIn, addrlen: u32) -> i32 {
    todo("Bind", "M9")
}

#[allow(non_snake_case, unused_variables)]
pub fn Listen(fd: i32, backlog: i32) -> i32 {
    todo("Listen", "M9")
}

#[allow(non_snake_case, unused_variables)]
pub fn Accept4(
    fd: i32,
    addr: *mut SockaddrIn,
    addrlen: *mut u32,
    flags: i32,
) -> i32 {
    todo("Accept4", "M9")
}

#[allow(non_snake_case, unused_variables)]
pub fn Connect(fd: i32, addr: *const SockaddrIn, addrlen: u32) -> i32 {
    todo("Connect", "M9")
}

#[allow(non_snake_case, unused_variables)]
pub fn Setsockopt(
    fd: i32,
    level: i32,
    name: i32,
    val: *const u8,
    len: u32,
) -> i32 {
    todo("Setsockopt", "M9")
}

#[allow(non_snake_case, unused_variables)]
pub fn SetsockoptInt(fd: crate::int, level: crate::int, opt: crate::int, value: crate::int) -> crate::error {
    todo("SetsockoptInt", "M9")
}

#[allow(non_snake_case, unused_variables)]
pub fn Getsockopt(
    fd: i32,
    level: i32,
    name: i32,
    val: *mut u8,
    len: *mut u32,
) -> i32 {
    todo("Getsockopt", "M9")
}

#[allow(non_snake_case, unused_variables)]
pub fn Shutdown(fd: i32, how: i32) -> i32 {
    todo("Shutdown", "M9")
}

#[allow(non_snake_case, unused_variables)]
pub fn Fcntl(fd: i32, cmd: i32, arg: i32) -> i32 {
    todo("Fcntl", "M9")
}

#[allow(non_snake_case, unused_variables)]
pub fn EpollCreate1(flags: i32) -> i32 {
    todo("EpollCreate1", "M9")
}

#[allow(non_snake_case, unused_variables)]
pub fn EpollCtl(
    epfd: i32,
    op: i32,
    fd: i32,
    event: *mut EpollEvent,
) -> i32 {
    todo("EpollCtl", "M9")
}

#[allow(non_snake_case, unused_variables)]
pub fn Eventfd(initval: u32, flags: i32) -> i32 {
    todo("Eventfd", "M9")
}

#[allow(non_snake_case, unused_variables)]
pub fn EpollPwait(
    epfd: i32,
    events: *mut EpollEvent,
    maxevents: i32,
    timeout_ms: i32,
    sigmask: *const u8,
    sigsetsize: usize,
) -> i32 {
    todo("EpollPwait", "M9")
}

#[allow(non_snake_case, unused_variables)]
pub fn InotifyInit1(flags: crate::int) -> (crate::int, crate::error) {
    todo("InotifyInit1", "M9")
}

#[allow(non_snake_case, unused_variables)]
pub fn InotifyAddWatch<P: Into<crate::string>>(
    fd: crate::int,
    pathname: P,
    mask: u32,
) -> (crate::int, crate::error) {
    todo("InotifyAddWatch", "M9")
}

#[allow(non_snake_case, unused_variables)]
pub fn InotifyRmWatch(fd: crate::int, watchdesc: u32) -> (crate::int, crate::error) {
    todo("InotifyRmWatch", "M9")
}

#[allow(non_snake_case, unused_variables)]
pub fn FanotifyInit(flags: u32, event_f_flags: u32) -> (crate::int, crate::error) {
    todo("FanotifyInit", "M9")
}

#[allow(non_snake_case, unused_variables)]
pub fn FanotifyMark<P: Into<crate::string>>(
    fd: crate::int,
    flags: u32,
    mask: u64,
    dirFd: crate::int,
    pathname: P,
) -> crate::error {
    todo("FanotifyMark", "M9")
}

#[allow(non_snake_case, unused_variables)]
pub fn NameToHandleAt<P: Into<crate::string>>(
    dirfd: crate::int,
    path: P,
    flags: crate::int,
) -> (FileHandle, crate::int, crate::error) {
    todo("NameToHandleAt", "M9")
}

#[allow(non_snake_case, unused_variables)]
pub fn Poll(fds: &mut [PollFd], timeout: crate::int) -> (crate::int, crate::error) {
    todo("Poll", "M9")
}

#[allow(non_snake_case, unused_variables)]
pub fn Statfs<P: Into<crate::string>>(path: P, buf: &mut Statfs_t) -> crate::error {
    todo("Statfs", "M2")
}


// ─── added with upstream's os.Root, Unix-socket and pprof surface ──────
//
// Linux gained these while the port was on a branch. Same signatures as
// `syscall_linux.rs`, each an abort naming the milestone that owns it:
// the fd-relative file calls are the M2 file surface, the raw socket
// calls are M9, and `Setitimer` drives pprof's SIGPROF, which is M6.

#[allow(non_snake_case, unused_variables)]
pub fn __openat_raw(dirfd: i32, path: *const u8, flags: i32, mode: i32) -> i32 {
    todo("__openat_raw", "M2")
}

#[allow(non_snake_case, unused_variables)]
pub fn Mkdirat(dirfd: i32, path: *const u8, mode: u32) -> i32 {
    todo("Mkdirat", "M2")
}

#[allow(non_snake_case, unused_variables)]
pub fn Unlinkat(dirfd: i32, path: *const u8, flags: i32) -> i32 {
    todo("Unlinkat", "M2")
}

#[allow(non_snake_case, unused_variables)]
pub fn Fstatat(dirfd: i32, path: *const u8, out: &mut Stat_t, flags: i32) -> i32 {
    todo("Fstatat", "M2")
}

#[allow(non_snake_case, unused_variables)]
pub fn Renameat(olddirfd: i32, oldpath: *const u8, newdirfd: i32, newpath: *const u8) -> i32 {
    todo("Renameat", "M2")
}

#[allow(non_snake_case, unused_variables)]
pub fn Linkat(
    olddirfd: i32,
    oldpath: *const u8,
    newdirfd: i32,
    newpath: *const u8,
    flags: i32,
) -> i32 {
    todo("Linkat", "M2")
}

#[allow(non_snake_case, unused_variables)]
pub fn Symlinkat(target: *const u8, newdirfd: i32, linkpath: *const u8) -> i32 {
    todo("Symlinkat", "M2")
}

#[allow(non_snake_case, unused_variables)]
pub fn Fchdir(fd: i32) -> i32 {
    todo("Fchdir", "M2")
}

#[allow(non_snake_case, unused_variables)]
pub fn Fchown(fd: i32, uid: u32, gid: u32) -> i32 {
    todo("Fchown", "M2")
}

#[allow(non_snake_case, unused_variables)]
pub fn Fchmodat(dirfd: i32, path: *const u8, mode: u32, flags: i32) -> i32 {
    todo("Fchmodat", "M2")
}

#[allow(non_snake_case, unused_variables)]
pub fn Fchownat(dirfd: i32, path: *const u8, uid: u32, gid: u32, flags: i32) -> i32 {
    todo("Fchownat", "M2")
}

#[allow(non_snake_case, unused_variables)]
pub fn Readlinkat(dirfd: i32, path: *const u8, buf: *mut u8, bufsiz: usize) -> isize {
    todo("Readlinkat", "M2")
}

#[allow(non_snake_case, unused_variables)]
pub fn __bind_raw(fd: i32, addr: *const u8, addrlen: u32) -> i32 {
    todo("__bind_raw", "M9")
}

#[allow(non_snake_case, unused_variables)]
pub fn __connect_raw(fd: i32, addr: *const u8, addrlen: u32) -> i32 {
    todo("__connect_raw", "M9")
}

#[allow(non_snake_case, unused_variables)]
pub fn __accept4_raw(fd: i32, addr: *mut u8, addrlen: *mut u32, flags: i32) -> i32 {
    todo("__accept4_raw", "M9")
}

#[allow(non_snake_case, unused_variables)]
pub fn Setitimer(which: i32, new: *const Itimerval, old: *mut Itimerval) -> i32 {
    todo("Setitimer", "M6")
}
