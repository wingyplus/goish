// sched::tls — the thread-pointer primitives, one file per target.
//
// goish plants each M's `MStorage` address in the thread pointer and
// keeps `tls_self` at offset 0, so `current_m()` is one load and the
// per-M `locks` counter is a fixed displacement off the same base.
// Which register holds that pointer, and how it is read and written, is
// the only per-target part — the policy above it (`acquirem`,
// `releasem`, the underflow tripwire, `setup_main_tls`) is written once
// in `sched/m.rs`.
//
// Go: `runtime/tls_arm64.h:9-13` maps GOOS_linux to `MRS TPIDR_EL0`,
// and `runtime/tls_arm64.s:21-26` reads it with no masking on Linux —
// the `AND $0xfffffffffffffff8` there is Darwin-only ("Darwin sometimes
// returns unaligned pointers"). amd64 uses `fs`, planted with
// `arch_prctl(2)`.
//
// `frame_pointer` and `stack_pointer` are `#[inline(always)]` in every
// file, and that is load-bearing, not a micro-optimisation. Their
// callers want *their own* register — `runtime::caller_rbp` is
// deliberately a one-frame helper and its callers' `skip` counts assume
// exactly that frame. A plain `#[inline]` is not honoured at opt-level
// 0, so a debug build called out and read the *callee's* x29/rbp: every
// `Callers`/`Caller` walk started one frame too deep, which CI caught as
// five caller-attribution failures on linux/amd64 after this facade
// replaced the inline `mov {}, rbp`.
//
// One property does NOT survive the port, and it is deliberate rather
// than an oversight. On amd64 `acquirem`/`releasem` are a single
// `lock add` / `lock xadd` against `fs:[off]`: the thread-pointer read
// and the read-modify-write are the same instruction, so the RMW cannot
// land on a different M's storage even if the thread is migrated
// between them. arm64 has no addressing mode that reaches through
// TPIDR_EL0, so the sequence is necessarily `mrs` then an atomic on the
// resulting address — two steps, with a window between them. See
// `tls_linux_arm64.rs` for what that does and does not cost.

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod tls_linux_amd64;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use tls_linux_amd64::*;

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod tls_linux_arm64;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use tls_linux_arm64::*;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod tls_darwin_arm64;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use tls_darwin_arm64::*;
