// runtime::rt0_darwin — the staged boot on macOS/arm64.
//
// The Linux `__goish_rt0` in `runtime/mod.rs` runs fifteen steps before
// it hands off to the user's `main`. This one runs seven. It is a
// separate function rather than a third `#[cfg]` arm threaded through
// that one because the difference is not a branch or two — it is which
// two thirds of the sequence exist at all, and a reader of either file
// should be able to see the whole boot without unpicking cfgs.
//
// ─── What runs ─────────────────────────────────────────────────────────
//
//   1. `args::__set`         — stash argc/argv for `os::Args()`.
//   2. `flags::init_from_envp` — GOISH_* knobs, from `main`'s third
//      argument rather than an ELF stack walk (see `runtime/flags.rs`).
//   3. `sched::setup_main_tls` — the main M's thread pointer, in a
//      pthread TSD slot (M4; see `sched/tls/tls_darwin_arm64.rs`).
//   4. `rand::init` — seed `select`'s fairness PRNG from `cputicks`.
//   5. `heap::mheap_init` + `mcentral::mcentral_init` — the allocator.
//   6. `sched::register_m_storage` + `sched::setup_main_g0` — the main
//      M's `g0`, adopting the OS stack from libpthread's bounds.
//   7. `__goish_main()`, then `sys::exit(0)`.
//
// **Step 5 is more than the port plan budgeted for**, and the reason is
// worth recording: the plan was written when `runtime/heap.rs` still
// had a pre-mheap dlmalloc tier, and scheduled M1 to boot on that and
// leave mheap for M2. dlmalloc is gone — `PageAlloc`'s metadata moved
// to raw `mmap`, so mheap and mcentral now need nothing but `Mmap`,
// which is real on this target from M1. Both come online here.
//
// The 320 GiB `MAP_NORESERVE` arena reservation was the one thing that
// looked likely to fail on a 16 KiB-page kernel with no overcommit
// accounting to opt out of. Measured before relying on it: macOS
// returns a mapping at 0x70_0000_0000 for exactly the size
// `map_arena(MAX_ARENA_CHUNKS)` asks for.
//
// ─── What does not run, and what that costs ────────────────────────────
//
// Skipped, each with the milestone that turns it on:
//
//   `bootstrap_ps`        M5
//   `bootstrap_workers`   M5 — `pthread_create` workers, which have
//                              nothing to run until `gogo` exists.
//   `start_sysmon`        M5 — a thread too; same reason.
//   SIGPIPE `SIG_IGN`     M6 — and Darwin has a better answer than the
//                              process-wide ignore: `SO_NOSIGPIPE` is
//                              per-socket. Nothing opens a socket yet.
//   `preempt::install`    M8
//   `symbolize::init`     M6 — mmaps `/proc/self/exe` and parses ELF.
//                              Permanently degraded here: DWARF is not
//                              in a linked Mach-O image, so backtraces
//                              will give `dladdr` symbol names and no
//                              `file:line`.
//   `segv::install`       M6
//
// The load-bearing consequence, and the same one linux/arm64 carries at
// M1: **the user's `main` runs directly on the OS stack, not on a
// goroutine**, because putting it on one needs `gogo` (M5). So
// `current_g()` is `None` throughout, and any blocking primitive —
// channel send/recv, `WaitGroup::Wait`, a contended `Mutex` — fatals
// with "outside of any goroutine" instead of parking, and `go!` itself
// aborts naming M5 (`scheduler::enqueue_runnable`) rather than queueing
// a G that nothing will ever run.
//
// M5 deletes the direct call; M6 deletes most of the list above.

use crate::runtime::{args, flags, heap, mcentral, rand, sched};
use crate::sys;

/// First Rust code to run after dyld calls `main`.
///
/// `extern "C"` and `#[no_mangle]` so the `main` that `#[goish::main]`
/// emits into the user's crate can call it across the C ABI, under the
/// same symbol name the Linux `_start` stubs use.
///
/// Diverges: the process exits from inside, either through the user's
/// own `syscall::Exit` or through the `sys::sys_exit(0)` at the foot —
/// which is Go's `runtime.main` shape, where the program ends when
/// `main` returns and whatever else was running stops where it stands.
#[no_mangle]
pub extern "C" fn __goish_rt0(
    argc: i32,
    argv: *const *const u8,
    envp: *const *const u8,
) -> ! {
    // Stash argc/argv so `os::Args()` can decode them lazily.
    args::__set(argc, argv);

    // GOISH_* knobs, before anything reads one. `envp` arrives as an
    // argument here; the `argv + argc + 1` walk the Linux path uses is
    // an ELF stack-layout fact and does not hold on this target.
    unsafe { flags::init_from_envp(envp) };

    // The main M's thread pointer: allocate the TSD key and plant
    // `&MAIN_M.tls_self` in it. From here `current_m()` works. Same
    // position as on Linux — before the allocator, because nothing in
    // it may take a SpinLock across the `TLS_READY` flip.
    sched::setup_main_tls();

    // Seed the cheaprand state so each run starts with a different
    // `select` fairness sequence. Same position as on Linux.
    rand::init();

    // Bring the allocator online. Both steps mmap directly and neither
    // routes through `#[global_allocator]`, so there is no bootstrap
    // cycle to break — see the file header on the dlmalloc removal.
    unsafe { heap::mheap_init() };
    unsafe {
        let arena_base = heap::mheap_arena_base();
        mcentral::mcentral_init(arena_base);
    }

    // Now that the allocator is up: register the main M so a waker
    // can find it, and give it a `g0` adopting the OS stack — from
    // libpthread's bounds rather than `/proc/self/maps`.
    sched::register_m_storage(&sched::MAIN_M);
    sched::setup_main_g0();

    // Hand off to the user's `main`. Directly, on this stack — see the
    // file header for why, and for what it costs.
    extern "C" {
        fn __goish_main();
    }
    unsafe { __goish_main() };

    // Go: `exit(0)` at the foot of `runtime.main`.
    unsafe { sys::sys_exit(0) }
}
