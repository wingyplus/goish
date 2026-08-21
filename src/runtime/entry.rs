// runtime::entry — the ELF entry stub, as a macro the user's crate
// expands.
//
// **Why a macro and not a function.** `_start` has to be emitted into
// the final binary's own object file, not into the rlib, or the linker
// never sees the symbol. `#[goish::main]` therefore expands a
// `global_asm!` into the user's crate.
//
// **Why the arch code is here and not in the proc macro.** A proc macro
// is compiled for and runs on the *host*, so `cfg!(target_arch = …)`
// inside `goish-macros` reads the host's values, not the target's —
// which is silently wrong the moment host and target differ, exactly
// the situation this port creates. `#[goish::main]` therefore emits a
// bare `::goish::__goish_entry!();` and the arch knowledge lives here,
// in an ordinary source file, where the `#[cfg]` is evaluated by rustc
// at target-compile time (the only correct time) and where the anchor
// and lint tooling can see it.
//
// This is the one place the plan's "separate files over inline `#[cfg]`
// arms" convention is not followed, and deliberately: `macro_rules!`
// has no per-file specialization, and splitting the two arms into
// `entry_linux_amd64.rs` / `entry_linux_arm64.rs` would require two
// `#[macro_export]` macros with the same name, which is not a thing.
// The arms below are the whole of the divergence.

/// The ELF entry stub. Expanded once, by `#[goish::main]`.
///
/// Both arms do the same four things: recover `argc`/`argv` from the
/// kernel-supplied stack, zero the frame-pointer register so a
/// frame-pointer unwinder stops here rather than walking into kernel-
/// supplied garbage (Go does the same — `runtime/asm_arm64.s:118`,
/// "Set the frame pointer register to 0 … won't attempt to unwind past
/// this function"), align the stack, and call `__goish_rt0`. The trap
/// instruction after the call is dead code — `__goish_rt0` is `-> !` —
/// and exists so an accidental return crashes loudly instead of
/// wandering.
#[macro_export]
#[doc(hidden)]
macro_rules! __goish_entry {
    () => {
        // Go: `runtime/asm_amd64.s` (`_rt0_amd64`) — argc at 0(SP),
        // argv at 8(SP).
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        ::core::arch::global_asm!(
            ".global _start",
            "_start:",
            "    mov rdi, [rsp]",
            "    lea rsi, [rsp + 8]",
            "    xor rbp, rbp",
            "    and rsp, -16",
            "    call __goish_rt0",
            "    ud2",
        );

        // Go: `runtime/asm_arm64.s:16-19` (`_rt0_arm64`) —
        //     MOVD 0(RSP), R0   // argc
        //     ADD  $8, RSP, R1  // argv
        // and `asm_arm64.s:118` `MOVD $0, R29` for the frame pointer.
        //
        // The align mirrors amd64's `and rsp, -16`, but has to go
        // through a scratch register: AND (immediate) accepts SP as the
        // destination and not as the source operand, so `and sp, sp,
        // #-16` does not encode. x9 is caller-saved and nothing is live
        // at process entry.
        //
        // The arm64 kernel already hands over a 16-aligned SP, so this
        // is belt-and-braces rather than load-bearing — but AAPCS64
        // requires SP to be 16-aligned at *every* instant, not merely at
        // call boundaries, so it is the one place where being sure is
        // free.
        //
        // `brk #0` is arm64's `ud2`.
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        ::core::arch::global_asm!(
            ".global _start",
            "_start:",
            "    ldr x0, [sp]",
            "    add x1, sp, #8",
            "    mov x29, #0",
            "    mov x9, sp",
            "    and x9, x9, #-16",
            "    mov sp, x9",
            "    bl __goish_rt0",
            "    brk #0",
        );
    };
}
