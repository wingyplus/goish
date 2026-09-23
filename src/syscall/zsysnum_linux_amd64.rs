// zsysnum_linux_amd64 - Linux/amd64 system-call numbers.
//
// Mirrors Go's `syscall/zsysnum_linux_amd64.go`, generated there from
// `/usr/include/asm/unistd_64.h`. Moved verbatim out of
// `syscall/mod.rs`; the only additions are the `*at` numbers at the
// bottom, which the wrappers now use on every architecture.

pub const SYS_READ: usize = 0;
pub const SYS_WRITE: usize = 1;
pub const SYS_OPEN: usize = 2;
pub const SYS_CLOSE: usize = 3;
pub const SYS_MMAP: usize = 9;
pub const SYS_MPROTECT: usize = 10;
pub const SYS_MUNMAP: usize = 11;
pub const SYS_MADVISE: usize = 28;
pub const SYS_CLONE: usize = 56;
pub const SYS_EXIT: usize = 60; // per-thread exit (vs SYS_EXIT_GROUP)
pub const SYS_SCHED_YIELD: usize = 24;
pub const SYS_NANOSLEEP: usize = 35;
pub const SYS_ARCH_PRCTL: usize = 158;
pub const SYS_GETTID: usize = 186;
pub const SYS_CLOCK_GETTIME: usize = 228;
pub const SYS_EXIT_GROUP: usize = 231;
pub const SYS_SCHED_GETAFFINITY: usize = 204;
pub const SYS_FUTEX: usize = 202;
pub const SYS_RT_SIGACTION: usize = 13;
pub const SYS_RT_SIGRETURN: usize = 15;
pub const SYS_GETPID: usize = 39;
pub const SYS_KILL: usize = 62;
pub const SYS_TGKILL: usize = 234;
pub const SYS_SIGALTSTACK: usize = 131;
pub const SYS_SOCKET: usize = 41;
pub const SYS_CONNECT: usize = 42;
pub const SYS_ACCEPT: usize = 43;
pub const SYS_SENDTO: usize = 44;
pub const SYS_RECVFROM: usize = 45;
pub const SYS_SHUTDOWN: usize = 48;
pub const SYS_BIND: usize = 49;
pub const SYS_LISTEN: usize = 50;
pub const SYS_GETSOCKNAME: usize = 51;
pub const SYS_GETPEERNAME: usize = 52;
pub const SYS_SOCKETPAIR: usize = 53;
pub const SYS_SETSOCKOPT: usize = 54;
pub const SYS_GETSOCKOPT: usize = 55;
pub const SYS_FCNTL: usize = 72;
pub const SYS_FSYNC: usize = 74;
pub const SYS_GETCWD: usize = 79;
pub const SYS_CHDIR: usize = 80;
pub const SYS_ACCEPT4: usize = 288;
pub const SYS_EPOLL_CREATE1: usize = 291;
pub const SYS_EPOLL_CTL: usize = 233;
pub const SYS_EPOLL_PWAIT: usize = 281;
pub const SYS_EVENTFD2: usize = 290;
pub const SYS_IOCTL: usize = 16;
pub const SYS_FORK: usize = 57;
pub const SYS_EXECVE: usize = 59;
pub const SYS_WAIT4: usize = 61;
pub const SYS_DUP2: usize = 33;
pub const SYS_DUP3: usize = 292;
pub const SYS_FSTAT: usize = 5;
pub const SYS_NEWFSTATAT: usize = 262;
pub const SYS_LSEEK: usize = 8;
pub const SYS_MKDIR: usize = 83;
pub const SYS_UNLINK: usize = 87;
pub const SYS_RMDIR: usize = 84;
pub const SYS_CHMOD: usize = 90;
pub const SYS_FCHMOD: usize = 91;
pub const SYS_SYMLINK: usize = 88;
pub const SYS_READLINK: usize = 89;
pub const SYS_RENAME: usize = 82;
pub const SYS_LINK: usize = 86;
pub const SYS_TRUNCATE: usize = 76;
pub const SYS_FTRUNCATE: usize = 77;
pub const SYS_PREAD64: usize = 17;
pub const SYS_PWRITE64: usize = 18;
pub const SYS_UTIMENSAT: usize = 280;
pub const SYS_FLOCK: usize = 73;
pub const SYS_PIPE2: usize = 293;
pub const SYS_CHOWN: usize = 92;
pub const SYS_LCHOWN: usize = 94;
pub const SYS_UNAME: usize = 63;
pub const SYS_GETRANDOM: usize = 318;
pub const SYS_GETDENTS64: usize = 217;
pub const SYS_GETUID: usize = 102;
pub const SYS_GETGID: usize = 104;
pub const SYS_GETEUID: usize = 107;
pub const SYS_GETEGID: usize = 108;
pub const SYS_GETPPID: usize = 110;
pub const SYS_GETGROUPS: usize = 115;
pub const SYS_POLL: usize = 7;
pub const SYS_INOTIFY_ADD_WATCH: usize = 254;
pub const SYS_INOTIFY_RM_WATCH: usize = 255;
pub const SYS_STATFS: usize = 137;
pub const SYS_INOTIFY_INIT1: usize = 294;
pub const SYS_FANOTIFY_INIT: usize = 300;
pub const SYS_FANOTIFY_MARK: usize = 301;
pub const SYS_NAME_TO_HANDLE_AT: usize = 303;

// --- the *at family ---------------------------------------------------
//
// arm64 has no legacy `open`/`mkdir`/`rename`/... at all - its table is
// generated from `asm-generic/unistd.h`, which only ever had the `*at`
// forms. Rather than carry a per-architecture fork of a dozen wrappers,
// goish calls the `*at` form with `AT_FDCWD` everywhere, which is what
// Go itself does: `syscall/syscall_linux.go:279-281` defines `func Open`
// as `openat(_AT_FDCWD, path, mode|O_LARGEFILE, perm)` for every Linux
// architecture, amd64 included.
pub const SYS_OPENAT: usize = 257;
pub const SYS_MKDIRAT: usize = 258;
pub const SYS_UNLINKAT: usize = 263;
pub const SYS_SYMLINKAT: usize = 266;
pub const SYS_LINKAT: usize = 265;
pub const SYS_RENAMEAT: usize = 264;
pub const SYS_READLINKAT: usize = 267;
pub const SYS_FCHMODAT: usize = 268;
pub const SYS_FCHOWNAT: usize = 260;
pub const SYS_PPOLL: usize = 271;

// Added upstream after the table split (os.Root's fd-relative surface
// and the pprof itimer); values from `syscall/zsysnum_linux_amd64.go`.
pub const SYS_FCHDIR: usize = 81;
pub const SYS_FCHOWN: usize = 93;
pub const SYS_MKNODAT: usize = 259;
pub const SYS_UMASK: usize = 95;
pub const SYS_GETITIMER: usize = 36;
pub const SYS_SETITIMER: usize = 38;
