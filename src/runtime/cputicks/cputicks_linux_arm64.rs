// cputicks_linux_arm64 — CLOCK_MONOTONIC nanoseconds, standing in for a
// cycle counter exactly as Go does.
//
// Go: `runtime/os_linux_arm64.go:18-22`
//
//     //go:nosplit
//     func cputicks() int64 {
//         // nanotime() is a poor approximation of CPU ticks that is
//         // enough for the profiler.
//         return nanotime()
//     }
//
// Worth stating plainly, because the obvious guess is wrong: arm64 does
// expose a counter to EL0 via `MRS CNTVCT_EL0`, and Go deliberately does
// not use it on Linux. Its frequency is the fixed system counter rate
// (typically 24 MHz), not the core clock, so it is not a "cycle" count
// in the sense RDTSC gives — and Go would need CNTFRQ_EL0 to interpret
// it. `nanotime()` is both cheaper to reason about and already correct.
//
// This is a seed source, so a vDSO fast path is not worth its
// complexity; the raw `clock_gettime(2)` goish already has is fine.

use crate::syscall::{self, Timespec, CLOCK_MONOTONIC};

/// `runtime.cputicks()` — nanoseconds since an arbitrary fixed point.
#[inline]
pub fn cputicks() -> u64 {
    let mut ts = Timespec { tv_sec: 0, tv_nsec: 0 };
    let _ = syscall::ClockGettime(CLOCK_MONOTONIC, &mut ts);
    (ts.tv_sec as u64).wrapping_mul(1_000_000_000).wrapping_add(ts.tv_nsec as u64)
}
