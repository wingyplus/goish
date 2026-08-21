// grow_asm_amd64 — leaf asm for the stack-growth path.
//
// Moved verbatim from `sched/grow.rs`.

use core::arch::naked_asm;

/// Returns the current value of RSP at the call site, accounting for
/// the 8 bytes the CALL instruction pushed. Mirrors `psm::stack_pointer`.
#[unsafe(naked)]
pub(crate) extern "C" fn current_sp() -> usize {
    naked_asm!(
        "lea rax, [rsp + 8]", // skip our own return address
        "ret",
    )
}

/// Pivot RSP onto `new_sp`, call `callback(data, ret_ptr)`, pivot back.
///
/// SysV ABI inputs:
///   rdi = data        — pointer to closure storage
///   rsi = ret_ptr     — pointer to MaybeUninit<R> for the return value
///   rdx = callback    — extern "sysv64" fn(*mut u8, *mut u8)
///   rcx = new_sp      — top of the new stack region (must be 16-aligned)
///
/// Saves old RBP/RSP via the standard prologue, pivots RSP to `rcx`,
/// runs `callback` (which reads the closure from `data` and writes the
/// result through `ret_ptr`), then restores via RBP. A normal `ret`
/// returns control on the original stack.
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn goish_on_stack(
    _data: *mut u8,
    _ret_ptr: *mut u8,
    _callback: extern "C" fn(*mut u8, *mut u8),
    _new_sp: *mut u8,
) {
    naked_asm!(
        "push rbp",
        "mov  rbp, rsp",
        "mov  rsp, rcx", // PIVOT to new stack
        "call rdx",      // rdi/rsi already correct
        "mov  rsp, rbp", // PIVOT back
        "pop  rbp",
        "ret",
    )
}
