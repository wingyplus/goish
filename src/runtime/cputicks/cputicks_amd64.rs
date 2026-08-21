// cputicks_amd64 — read the x86 timestamp counter.
//
// Go: `runtime/asm_amd64.s:1255` (`runtime·cputicks`). Go picks RDTSCP
// over RDTSC+LFENCE when `X86.HasRDTSCP` is set, purely to get
// instruction-stream serialization; goish has no CPU-feature table yet
// (that is M11) and uses the value only as a startup seed, so the plain
// RDTSC form below is the honest subset rather than a fake of Go's
// dispatch.
//
// Moved verbatim from `runtime/rand.rs`, where it was `fn rdtsc()`.

/// `runtime.cputicks()` — 64-bit timestamp counter, `edx:eax`.
#[inline]
pub fn cputicks() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nostack, preserves_flags, nomem),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}
