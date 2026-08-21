// runtime::cputicks — Go's `cputicks()`, one file per target.
//
// Go declares it as a bodyless `func cputicks() int64` in
// `runtime/cputicks.go:11` and supplies a per-platform definition. The
// two that matter here are genuinely different in kind, not just in
// instruction:
//
//   * amd64 reads the timestamp counter directly (`asm_amd64.s:1255`,
//     RDTSCP when available, else RDTSC + fences).
//   * linux/arm64 does NOT read `CNTVCT_EL0`. `os_linux_arm64.go:18-22`
//     is `return nanotime()`, with Go's own comment: "nanotime() is a
//     poor approximation of CPU ticks that is enough for the profiler."
//     (Darwin/arm64 differs again — `os_darwin_arm64.go:8` calls
//     `mach_absolute_time`.)
//
// goish uses this in exactly one place — seeding `runtime::rand`'s
// wyrand state once at startup — so "enough for the profiler" is more
// than enough here. Following Go rather than reaching for `MRS
// CNTVCT_EL0` also keeps every line citable, which is the whole point.

#[cfg(target_arch = "x86_64")]
mod cputicks_amd64;
#[cfg(target_arch = "x86_64")]
pub use cputicks_amd64::cputicks;

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod cputicks_linux_arm64;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use cputicks_linux_arm64::cputicks;
