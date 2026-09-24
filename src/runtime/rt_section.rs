// runtime::rt_section — preempt-unsafe runtime PC range.
//
// Mirrors Go's "never preempt runtime code" filter
// (preempt.go:420 `name.HasPrefix("runtime.")`).
//
// Mechanism: every preempt-unsafe function in the goish runtime is
// tagged with `#[link_section = ...]` + `#[inline(never)]`.
// The ELF linker auto-generates `__start_goish_rt_text` and
// `__stop_goish_rt_text` symbols pointing to the section's bounds
// because the section name is a valid C identifier (System V ABI).
// The SIGURG handler checks the saved RIP against this range and
// skips injection when the PC falls inside.
//
// **Neither half of that survives on Mach-O**, which is why the 46 tag
// sites carry a `cfg_attr` pair and this file has a Darwin arm:
//
//   * A Mach-O section name is a `"__SEGMENT,__section"` pair, so the
//     bare `"goish_rt_text"` is not merely unconventional there — rustc
//     rejects it outright ("invalid Mach-O section specifier"). The
//     Darwin spelling is
//     `"__TEXT,__goish_rt_text,regular,pure_instructions"`. The two
//     trailing attributes are not decoration: without them ld64 treats
//     the section as data, and since the functions placed there carry
//     unwind information it warns that "symbols ... have unwind
//     information, but it's not a code section". A section of runtime
//     code that the linker does not believe is code is precisely the
//     wrong footing for the M8 PC-range check that will read it.
//   * ld64 generates no `__start_`/`__stop_` bound symbols; its own
//     spelling is `section$start$__TEXT$__goish_rt_text` and
//     `section$end$…`, defined for any section it links. Those are
//     link-time symbols like the ELF pair, so both targets answer
//     `is_in_runtime()` the same way.
//
// **Why we need it**. The `m.locks` counter is an upper bound on
// preempt-unsafe regions: every SpinLock guard bumps it. But there
// are short windows where `m.locks == 0` while the runtime is still
// in the middle of a non-atomic mutation (e.g., between
// `drop_m_locks()` and `atom.store(false)` in `raw_unlock`,
// between the status flip and the runq enqueue in `goready`,
// between the slot write and the runqtail store-release in
// `runqput`). SIGURG injecting in any of those windows leaves the
// runtime in a half-mutated state when the G yields. Go has the
// same windows but its handler also rejects on
// `name.HasPrefix("runtime.")`. We mirror that defense in depth.
//
// **Why `#[inline(never)]` is mandatory**. With LTO and codegen-
// units=1, a small `link_section`-tagged function can be inlined
// into a non-tagged caller (typically user code or a higher-level
// library helper). The inlined bytes end up in the caller's text
// section, NOT in `goish_rt_text`. The handler would then fail to
// recognize them as runtime code and inject anyway. `#[inline(never)]`
// preserves the function as its own callable site so the section
// attribute actually places it.

use core::sync::atomic::AtomicU64;

#[cfg(not(target_os = "macos"))]
extern "C" {
    /// First byte of the `goish_rt_text` section.
    pub static __start_goish_rt_text: u8;
    /// Byte just past the last byte of the `goish_rt_text` section.
    pub static __stop_goish_rt_text: u8;
}

/// True iff `pc` falls inside any function tagged
/// `#[link_section = "goish_rt_text"]`.
///
/// Used by the SIGURG preempt handler to refuse injection on
/// runtime PCs (mirrors Go's `name.HasPrefix("runtime.")` check at
/// runtime/preempt.go:420).
#[cfg(not(target_os = "macos"))]
#[inline]
pub fn is_in_runtime(pc: u64) -> bool {
    let start = unsafe { &__start_goish_rt_text as *const u8 as u64 };
    let end = unsafe { &__stop_goish_rt_text as *const u8 as u64 };
    pc >= start && pc < end
}

// ld64's spelling of `__start_`/`__stop_`: for any section it links,
// it defines `section$start$SEG$SECT` and `section$end$SEG$SECT`. The
// leading `\x01` tells LLVM to emit the name verbatim, without the
// Mach-O `_` prefix — ld64 matches the undecorated form.
#[cfg(target_os = "macos")]
extern "C" {
    #[link_name = "\x01section$start$__TEXT$__goish_rt_text"]
    static __start_goish_rt_text: u8;
    #[link_name = "\x01section$end$__TEXT$__goish_rt_text"]
    static __stop_goish_rt_text: u8;
}

/// Darwin: the same test, over ld64's synthesized section bounds.
/// The PIE slide moves the symbols with the code, so no adjustment.
#[cfg(target_os = "macos")]
#[inline]
pub fn is_in_runtime(pc: u64) -> bool {
    let (start, end, _) = section_bounds();
    pc >= start && pc < end
}

/// Diagnostic counter: SIGURG firings the handler skipped due to
/// PC falling inside `goish_rt_text`. Bumped by the handler
/// (preempt.rs).
pub static SKIP_RUNTIME_PC: AtomicU64 = AtomicU64::new(0);

/// Snapshot of the `goish_rt_text` section bounds. Returns
/// `(start, end, length)`. Diagnostic — used by tests to verify
/// the section was populated and that tagged functions land
/// inside it.
#[cfg(not(target_os = "macos"))]
pub fn section_bounds() -> (u64, u64, u64) {
    let start = unsafe { &__start_goish_rt_text as *const u8 as u64 };
    let end = unsafe { &__stop_goish_rt_text as *const u8 as u64 };
    (start, end, end.wrapping_sub(start))
}

/// Darwin: ld64's `section$start`/`section$end` for
/// `__TEXT,__goish_rt_text`.
#[cfg(target_os = "macos")]
pub fn section_bounds() -> (u64, u64, u64) {
    let start = unsafe { &__start_goish_rt_text as *const u8 as u64 };
    let end = unsafe { &__stop_goish_rt_text as *const u8 as u64 };
    (start, end, end.wrapping_sub(start))
}

/// Anchor function: ensures `goish_rt_text` is non-empty so the
/// linker emits `__start_*` / `__stop_*` symbols even if no other
/// function is tagged yet (during incremental rollout). Always
/// safe to keep — it's just a marker.
#[inline(never)]
#[cfg_attr(not(target_os = "macos"), link_section = "goish_rt_text")]
#[cfg_attr(target_os = "macos", link_section = "__TEXT,__goish_rt_text,regular,pure_instructions")]
#[no_mangle]
pub extern "C" fn __goish_rt_text_anchor() -> u64 {
    // Reference our own address to defeat dead-code elimination of
    // the function body.
    __goish_rt_text_anchor as *const () as u64
}

// Force the linker to keep `__goish_rt_text_anchor` even when no
// caller references it from the leaf binary. Without this, LTO can
// strip the only function placed in `goish_rt_text`, causing the
// section to be empty and the auto-generated `__start_*`/`__stop_*`
// symbols to be undefined at link time.
#[used]
static __ANCHOR_KEEP: extern "C" fn() -> u64 = __goish_rt_text_anchor;
