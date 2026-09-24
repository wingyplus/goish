// grow_asm_arm64 — leaf asm for the stack-growth path.
//
// Unlike the context-switch primitives next door, both of these port
// cleanly, because neither depends on where the return address lives
// across a *switch* — only across a single call, which `x30` and the
// AAPCS64 frame record handle directly.

use core::arch::naked_asm;

/// Returns the current value of SP at the call site.
///
/// The amd64 version adds 8 to skip the return address `call` pushed.
/// AAPCS64 has no such adjustment to make: `bl` leaves the return
/// address in `x30` and pushes nothing, so SP at entry already *is* the
/// caller's SP.
#[unsafe(naked)]
pub(crate) extern "C" fn current_sp() -> usize {
    naked_asm!(
        "mov x0, sp",
        "ret",
    )
}

/// Pivot SP onto `new_sp`, call `callback(data, ret_ptr)`, pivot back.
///
/// AAPCS64 inputs:
///   x0 = data        — pointer to closure storage
///   x1 = ret_ptr     — pointer to MaybeUninit<R> for the return value
///   x2 = callback    — extern "C" fn(*mut u8, *mut u8)
///   x3 = new_sp      — top of the new stack region (must be 16-aligned)
///
/// `stp x29, x30` is the AAPCS64 frame record — it saves the frame
/// pointer and the return address together, doing the job of amd64's
/// `push rbp` *and* the return address `call` had already pushed. x29
/// then anchors the pivot back, exactly as rbp does on amd64.
///
/// SP must stay 16-byte aligned at every instant on arm64, not merely
/// at call boundaries; `new_sp` is required to be aligned by contract
/// and the frame record is a paired 16-byte push, so both halves hold.
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn goish_on_stack(
    _data: *mut u8,
    _ret_ptr: *mut u8,
    _callback: extern "C" fn(*mut u8, *mut u8),
    _new_sp: *mut u8,
) {
    naked_asm!(
        "stp x29, x30, [sp, #-16]!",
        "mov x29, sp",
        "mov sp, x3",  // PIVOT to new stack
        "blr x2",      // x0/x1 already correct
        "mov sp, x29", // PIVOT back
        "ldp x29, x30, [sp], #16",
        "ret",
    )
}
