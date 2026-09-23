// cputicks_darwin_arm64 — `mach_absolute_time`, standing in for a cycle
// counter exactly as Go does.
//
// Go: `runtime/os_darwin_arm64.go:7-11`
//
//     //go:nosplit
//     func cputicks() int64 {
//         // runtime·nanotime() is a poor approximation of CPU ticks
//         // that is enough for the profiler.
//         return nanotime()
//     }
//
// — the same two lines as `os_linux_arm64.go:18-22`, so the *policy*
// ports with no change at all. Only the clock underneath differs:
// Darwin's `nanotime1` (`runtime/sys_darwin.go:304-320`) reads
// `mach_absolute_time()` and scales it by the `mach_timebase_info`
// numerator/denominator, where the Linux file issues
// `clock_gettime(CLOCK_MONOTONIC)`.
//
// The scaling is deliberately not done here. goish's single caller is
// `runtime::rand`'s startup seed, which wants monotonic bits and no
// unit, so raw ticks serve. They are **not** nanoseconds: Go's comment
// that `numer == denom == 1` is common does not hold on Apple Silicon,
// where the timebase measures 125/3 (a 24 MHz counter). Nanoseconds come
// from `clock_gettime(CLOCK_UPTIME_RAW)` — see `runtime::sysmon::
// NANOTIME_CLOCK`.
//
// The alternative, `MRS CNTVCT_EL0`, is available at EL0 on this
// hardware and is not what Go uses on any OS — see the note in
// `cputicks_linux_arm64.rs` for why (fixed system counter rate, not the
// core clock, and uninterpretable without `CNTFRQ_EL0`).

/// `runtime.cputicks()` — monotonic ticks since an arbitrary fixed point.
#[inline]
pub fn cputicks() -> u64 {
    unsafe { crate::sys::sys_mach_absolute_time() }
}
