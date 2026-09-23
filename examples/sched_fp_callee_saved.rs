// Smoke test: arm64 context switches preserve d8–d15.
//
// AAPCS64 makes the low 64 bits of v8–v15 callee-saved; SysV has no
// callee-saved FP registers at all, which is why the amd64 `Gobuf`
// carries none and a transliterated arm64 one would silently drop them.
// Nothing crashes when that happens — a float in some resumed Rust frame
// is just wrong — so this test makes it observable.
//
// Each of 8 goroutines, 100 times: load distinct values into d8–d15,
// call `Gosched` (which switches to the other goroutines, each doing the
// same with different values), and read d8–d15 back. The helper is
// naked asm so the values are in exactly those registers across the
// call, which a debug build would never arrange on its own.
//
// Verified to fail: with `gogo`'s four `ldp d*` restores deleted, this
// reports 800 of 800 mismatches.
//
// On x86_64 it prints a skip line and exits 0 — there is nothing to test.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU32, Ordering};

#[cfg(target_arch = "aarch64")]
static DONE: AtomicU32 = AtomicU32::new(0);
#[cfg(target_arch = "aarch64")]
static BAD: AtomicU32 = AtomicU32::new(0);

#[cfg(target_arch = "aarch64")]
extern "C" fn yield_now() {
    goish::runtime::sched::Gosched();
}

/// Load d8..d15 from `vals`, call `f`, store d8..d15 to `out`. Honours
/// AAPCS64 itself (saves and restores its own d8–d15, x19, x29, x30),
/// so any difference between `vals` and `out` means `f` clobbered them.
#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
extern "C" fn fp_roundtrip(_vals: *const f64, _out: *mut f64, _f: extern "C" fn()) {
    core::arch::naked_asm!(
        "stp x29, x30, [sp, #-96]!",
        "mov x29, sp",
        "stp d8, d9, [sp, #16]",
        "stp d10, d11, [sp, #32]",
        "stp d12, d13, [sp, #48]",
        "stp d14, d15, [sp, #64]",
        "stp x19, x20, [sp, #80]",
        "mov x19, x1",
        "ldp d8, d9, [x0, #0]",
        "ldp d10, d11, [x0, #16]",
        "ldp d12, d13, [x0, #32]",
        "ldp d14, d15, [x0, #48]",
        "blr x2",
        "stp d8, d9, [x19, #0]",
        "stp d10, d11, [x19, #16]",
        "stp d12, d13, [x19, #32]",
        "stp d14, d15, [x19, #48]",
        "ldp x19, x20, [sp, #80]",
        "ldp d8, d9, [sp, #16]",
        "ldp d10, d11, [sp, #32]",
        "ldp d12, d13, [sp, #48]",
        "ldp d14, d15, [sp, #64]",
        "ldp x29, x30, [sp], #96",
        "ret",
    )
}

#[cfg(target_arch = "aarch64")]
#[goish::main]
fn main() {
    for g in 0..8u32 {
        goish::go!(move || {
            for round in 0..100u32 {
                let mut vals = [0f64; 8];
                for k in 0..8 {
                    vals[k] = (g * 1000 + round * 10 + k as u32) as f64 + 0.5;
                }
                let mut out = [0f64; 8];
                fp_roundtrip(vals.as_ptr(), out.as_mut_ptr(), yield_now);
                if out != vals {
                    BAD.fetch_add(1, Ordering::Relaxed);
                }
            }
            DONE.fetch_add(1, Ordering::Release);
        });
    }
    while DONE.load(Ordering::Acquire) < 8 {
        goish::runtime::sched::Gosched();
    }
    let n = BAD.load(Ordering::Relaxed);
    goish::fmt::Println!("sched_fp_callee_saved: 8 goroutines x 100 switches, mismatches:", n);
    if n != 0 {
        goish::syscall::Exit(1);
    }
}

#[cfg(not(target_arch = "aarch64"))]
#[goish::main]
fn main() {
    let _ = AtomicU32::new(0).load(Ordering::Relaxed);
    goish::fmt::Println!("sched_fp_callee_saved: skipped (no callee-saved FP registers on this arch)");
}
