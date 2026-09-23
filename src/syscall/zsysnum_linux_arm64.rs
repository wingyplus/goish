// zsysnum_linux_arm64 - Linux/arm64 system-call numbers.
//
// Mirrors Go's `syscall/zsysnum_linux_arm64.go`, whose own header records
// where the numbers come from: `mksysnum_linux.pl
// /usr/include/asm-generic/unistd.h`. Every value below was read out of
// that file rather than derived.
//
// **This is not a renumbering of the amd64 table.** arm64 was added to
// Linux after the `*at` family existed, so it never got the legacy
// calls: there is no `open`, `mkdir`, `rmdir`, `unlink`, `rename`,
// `link`, `symlink`, `readlink`, `chmod`, `chown`, `lchown`, `poll`,
// `dup2`, `fork`, `pipe`, `epoll_create` or `arch_prctl` at any number.
// Go hits the same wall and answers it the same way - see the note in
// `zsysnum_linux_amd64.rs` on `syscall_linux.go:279-281`, and
// `syscall_linux_arm64.go:16`, where Go binds `EpollWait` to
// `SYS_EPOLL_PWAIT` because plain `epoll_wait` is another casualty.
// goish was already on `epoll_create1`/`epoll_ctl`/`epoll_pwait`, so the
// netpoller needed nothing.
//
// The one name deliberately absent here is `SYS_ARCH_PRCTL`: planting
// the thread pointer is not a syscall on arm64 at all (`msr tpidr_el0`),
// so that difference is handled in `runtime/sched/tls/`, not by a number.

pub const SYS_READ: usize = 63;
pub const SYS_WRITE: usize = 64;
pub const SYS_CLOSE: usize = 57;
pub const SYS_MMAP: usize = 222;
pub const SYS_MPROTECT: usize = 226;
pub const SYS_MUNMAP: usize = 215;
pub const SYS_MADVISE: usize = 233;
pub const SYS_CLONE: usize = 220;
pub const SYS_EXIT: usize = 93;
pub const SYS_SCHED_YIELD: usize = 124;
pub const SYS_NANOSLEEP: usize = 101;
pub const SYS_GETTID: usize = 178;
pub const SYS_CLOCK_GETTIME: usize = 113;
pub const SYS_EXIT_GROUP: usize = 94;
pub const SYS_SCHED_GETAFFINITY: usize = 123;
pub const SYS_FUTEX: usize = 98;
pub const SYS_RT_SIGACTION: usize = 134;
pub const SYS_RT_SIGRETURN: usize = 139;
pub const SYS_GETPID: usize = 172;
pub const SYS_KILL: usize = 129;
pub const SYS_TGKILL: usize = 131;
pub const SYS_SIGALTSTACK: usize = 132;
pub const SYS_SOCKET: usize = 198;
pub const SYS_CONNECT: usize = 203;
pub const SYS_ACCEPT: usize = 202;
pub const SYS_SENDTO: usize = 206;
pub const SYS_RECVFROM: usize = 207;
pub const SYS_SHUTDOWN: usize = 210;
pub const SYS_BIND: usize = 200;
pub const SYS_LISTEN: usize = 201;
pub const SYS_GETSOCKNAME: usize = 204;
pub const SYS_GETPEERNAME: usize = 205;
pub const SYS_SOCKETPAIR: usize = 199;
pub const SYS_SETSOCKOPT: usize = 208;
pub const SYS_GETSOCKOPT: usize = 209;
pub const SYS_FCNTL: usize = 25;
pub const SYS_FSYNC: usize = 82;
pub const SYS_GETCWD: usize = 17;
pub const SYS_CHDIR: usize = 49;
pub const SYS_ACCEPT4: usize = 242;
pub const SYS_EPOLL_CREATE1: usize = 20;
pub const SYS_EPOLL_CTL: usize = 21;
pub const SYS_EPOLL_PWAIT: usize = 22;
pub const SYS_EVENTFD2: usize = 19;
pub const SYS_IOCTL: usize = 29;
pub const SYS_EXECVE: usize = 221;
pub const SYS_WAIT4: usize = 260;
pub const SYS_DUP3: usize = 24;
pub const SYS_FSTAT: usize = 80;
pub const SYS_LSEEK: usize = 62;
pub const SYS_FCHMOD: usize = 52;
pub const SYS_TRUNCATE: usize = 45;
pub const SYS_FTRUNCATE: usize = 46;
pub const SYS_PREAD64: usize = 67;
pub const SYS_PWRITE64: usize = 68;
pub const SYS_UTIMENSAT: usize = 88;
pub const SYS_FLOCK: usize = 32;
pub const SYS_PIPE2: usize = 59;
pub const SYS_UNAME: usize = 160;
pub const SYS_GETRANDOM: usize = 278;
pub const SYS_GETDENTS64: usize = 61;
pub const SYS_GETUID: usize = 174;
pub const SYS_GETGID: usize = 176;
pub const SYS_GETEUID: usize = 175;
pub const SYS_GETEGID: usize = 177;
pub const SYS_GETPPID: usize = 173;
pub const SYS_GETGROUPS: usize = 158;
pub const SYS_INOTIFY_ADD_WATCH: usize = 27;
pub const SYS_INOTIFY_RM_WATCH: usize = 28;
pub const SYS_STATFS: usize = 43;
pub const SYS_INOTIFY_INIT1: usize = 26;
pub const SYS_FANOTIFY_INIT: usize = 262;
pub const SYS_FANOTIFY_MARK: usize = 263;
pub const SYS_NAME_TO_HANDLE_AT: usize = 264;

/// arm64 calls it `fstatat`, amd64 calls it `newfstatat`; same call.
/// Go: `syscall/zsysnum_linux_arm64.go` `SYS_FSTATAT = 79`.
pub const SYS_NEWFSTATAT: usize = 79;

// --- the *at family ---------------------------------------------------
//
// On arm64 these are not an alternative to the legacy calls - they are
// the only calls. See the header.
pub const SYS_OPENAT: usize = 56;
pub const SYS_MKDIRAT: usize = 34;
pub const SYS_UNLINKAT: usize = 35;
pub const SYS_SYMLINKAT: usize = 36;
pub const SYS_LINKAT: usize = 37;
pub const SYS_RENAMEAT: usize = 38;
pub const SYS_READLINKAT: usize = 78;
pub const SYS_FCHMODAT: usize = 53;
pub const SYS_FCHOWNAT: usize = 54;
pub const SYS_PPOLL: usize = 73;

// Added upstream after the table split (os.Root's fd-relative surface
// and the pprof itimer); values from `syscall/zsysnum_linux_arm64.go`.
// No `SYS_MKNOD`: arm64 has only `mknodat` (33), and the wrapper takes
// the `*at` form on both architectures, as the others here do.
pub const SYS_FCHDIR: usize = 50;
pub const SYS_FCHOWN: usize = 55;
pub const SYS_MKNODAT: usize = 33;
pub const SYS_UMASK: usize = 166;
pub const SYS_GETITIMER: usize = 102;
pub const SYS_SETITIMER: usize = 103;
