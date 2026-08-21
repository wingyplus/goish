// sys — the raw system-call instruction, and nothing else.
//
// This module is the ONLY place in goish where a `syscall` / `svc`
// instruction, or an `extern "C"` declaration of a host libc, may
// appear. Everything above it — all ~96 Go-shaped wrappers in
// `crate::syscall`, and every caller of those — is written once and
// stays target-independent.
//
// The contract every backend implements:
//
//   syscallN(n, a1..aN) -> isize
//
// returning the raw kernel result: a non-negative value on success, or
// a negative `-errno` on failure. That is Linux's native convention on
// both amd64 and arm64, so both backends are a straight instruction
// swap. It is NOT Darwin's convention (carry flag + `errno`), which is
// exactly why the negative-errno shape is pinned down here as goish's
// internal ABI rather than left implicit: a Darwin backend adapts to
// this, and no caller changes.
//
// Per-target files rather than inline `#[cfg]` arms, matching Go's own
// `_GOOS_GOARCH` suffix convention. A cfg'd-out file still exists on
// disk, so the source-parsing tooling (anchor_check.py, port_lint.py,
// port_coverage.py) can see arm64 code from an amd64 host and back.

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod sys_linux_amd64;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use sys_linux_amd64::*;

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod sys_linux_arm64;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use sys_linux_arm64::*;
