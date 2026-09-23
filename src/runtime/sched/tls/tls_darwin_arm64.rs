// tls_darwin_arm64 — the thread pointer on macOS/arm64.
//
// ─── Why `set_base` cannot simply `msr tpidr_el0` ─────────────────────
//
// On Linux/arm64, `TPIDR_EL0` is writable at EL0 and belongs to
// whoever gets there first, so goish plants each M's `MStorage` address
// in it and `current_m()` is one load. On Darwin the thread's TSD
// (thread-specific data) array belongs to libSystem: every `pthread_*`
// call, the ObjC runtime and the malloc zones read through it, and its
// base is in `TPIDRRO_EL0` — *read-only* at EL0. There is no register
// for goish to plant.
//
// ─── What goish does instead: Go's `tlsinit`, one slot in that array ──
//
// Go shares the array rather than replacing it (`runtime/tls_arm64.h`
// selects `MRS TPIDRRO_EL0` under `TLS_darwin`):
//
//   1. once, at boot: `pthread_key_create`, `pthread_setspecific(key,
//      magic)`, then scan the TSD array for the magic to learn the
//      key's byte offset (`runtime/sys_darwin_arm64.go`, `tlsinit`);
//   2. every read: `MRS TPIDRRO_EL0`, mask the low three bits ("Darwin
//      sometimes returns unaligned pointers"), load at that offset
//      (`runtime/tls_arm64.s`, `load_g`);
//   3. every write: the same address, a plain store (`save_g`) — no
//      `pthread_setspecific` on the hot path in either direction.
//
// So "read-only" applies to the register, not to the array it points
// at, and goish's thread pointer is **the contents of one TSD slot**:
// `base()` returns what `set_base` stored there — `&MStorage.tls_self`,
// exactly the value `fs`/`TPIDR_EL0` hold on Linux — and `slot0()` loads
// through it. Everything above this file (`current_m`, `acquirem`,
// `locks_inc::<OFF>` as `base + OFF`) ports unchanged.
//
// The port plan's M4 row said to ship `pthread_getspecific` first and
// take the `MRS` path later "once `tls_arm64.s` has been read". It has
// been, and the direct read is taken now for a reason that is not speed:
// `acquirem`/`releasem` live in `goish_rt_text`, and a
// `pthread_getspecific` would put a call into libSystem's `.text` —
// outside the range M8's SIGURG handler treats as runtime code — inside
// the window those two exist to protect. The library call is used once,
// in `init`, to prove the direct read agrees with it.
//
// ─── The cost, the same as linux/arm64 ─────────────────────────────────
//
// The slot read and the atomic on `base + OFF` are separate
// instructions, so amd64's single-instruction `lock add fs:[off]`
// guarantee is not reproduced — here it takes *three* steps (register,
// slot, RMW) rather than two. The argument for why that is survivable
// is the one in `tls_linux_arm64.rs::locks_inc` and does not change:
// no migration without a park, and `acquirem` forbids parking.
//
// ─── Workers ───────────────────────────────────────────────────────────
//
// Linux plants a worker's thread pointer with `CLONE_SETTLS`,
// atomically with thread creation. `pthread_create` has no equivalent,
// so a Darwin worker's start routine must call `set_base` before
// anything takes a `SpinLock` — until then `acquirem` would find a zero
// slot. That lands with the worker Ms, in M5.

use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use crate::sys;

/// Byte offset of goish's key within the TSD array. **Zero means "not
/// yet initialised"** — no key `pthread_key_create` hands a caller can
/// sit at slot 0, which libpthread reserves for the thread's own
/// `pthread_t` — so the fast path can test it without a second flag.
static TLS_OFF: AtomicUsize = AtomicUsize::new(0);

/// `_PTHREAD_KEYS_MAX` — the TSD array's length, and the bound on the
/// scan. Go: `runtime/defs_darwin_arm64.go`.
const PTHREAD_KEYS_MAX: usize = 512;

/// Written by `init` and searched for; any value no real slot holds.
/// Go's own constant, from `tlsinit`.
const MAGIC: usize = 0xc476c475c47957;

/// Report a fatal TLS condition and exit 2. Cold, so the check that
/// reaches it costs one compare on the hot path.
#[cold]
#[inline(never)]
fn fatal(what: &[u8]) -> ! {
    let msg = b"goish: darwin/arm64 thread pointer: ";
    crate::syscall::Write(crate::syscall::STDERR, msg.as_ptr(), msg.len());
    crate::syscall::Write(crate::syscall::STDERR, what.as_ptr(), what.len());
    crate::syscall::Write(crate::syscall::STDERR, b"\n".as_ptr(), 1);
    crate::syscall::Exit(2)
}

/// The TSD array's base: `TPIDRRO_EL0` with the low three bits masked,
/// exactly as Go's `load_g` does.
#[inline(always)]
unsafe fn tsd() -> usize {
    let tp: usize;
    core::arch::asm!(
        "mrs {0}, tpidrro_el0",
        out(reg) tp,
        options(nomem, nostack, preserves_flags),
    );
    tp & !7
}

/// Address of goish's slot in the calling thread's TSD array.
///
/// Before `init` this would be slot 0 — the thread's `pthread_t`, a
/// valid pointer — and a load through it would return plausible garbage
/// rather than fault. So the uninitialised case aborts loudly here
/// instead, keeping the property Linux gets for free from a null
/// thread pointer.
#[inline(always)]
unsafe fn slot() -> *mut usize {
    let off = TLS_OFF.load(Ordering::Relaxed);
    if off == 0 {
        fatal(b"read before setup_main_tls allocated the TSD key");
    }
    (tsd() + off) as *mut usize
}

/// Allocate goish's TSD key and learn its offset. Must run once, on the
/// main thread, before the first `set_base`.
///
/// Go: `runtime/sys_darwin_arm64.go` `tlsinit`, called from `rt0_go`
/// in `runtime/asm_arm64.s` under `TLS_darwin`.
pub unsafe fn init() {
    let key = match sys::sys_pthread_key_create() {
        Ok(k) => k,
        Err(_) => fatal(b"pthread_key_create failed"),
    };
    if sys::sys_pthread_setspecific(key, MAGIC) != 0 {
        fatal(b"pthread_setspecific failed");
    }
    let arr = tsd() as *const usize;
    let mut i = 1;
    while i < PTHREAD_KEYS_MAX {
        if *arr.add(i) == MAGIC {
            TLS_OFF.store(i * core::mem::size_of::<usize>(), Ordering::Relaxed);
            let _ = sys::sys_pthread_setspecific(key, 0);
            // Cross-check the direct path against the library once:
            // write through the slot, read back through libpthread. If
            // a future macOS moved the array, this is where it shows.
            *slot() = MAGIC;
            let back = sys::sys_pthread_getspecific(key);
            *slot() = 0;
            if back != MAGIC {
                fatal(b"TSD slot and pthread_getspecific disagree");
            }
            return;
        }
        i += 1;
    }
    fatal(b"pthread key not found in the TSD array")
}

/// Value at thread-pointer offset 0 — `current_m()`'s fast path.
///
/// **Must not be called before this thread's base is planted.** An
/// unplanted slot holds 0, and this dereferences it — a fault, as on
/// Linux.
#[inline]
pub unsafe fn slot0() -> usize {
    *(*slot() as *const usize)
}

/// The thread-pointer base: what `set_base` stored in goish's slot.
///
/// Zero before `init` and on a thread that has not planted one, which
/// is also what Linux's static build reports — so `setup_main_tls`
/// saves no "pre-goish base", correctly: there is no foreign TCB here
/// to preserve, libSystem's lives in the rest of the array untouched.
#[inline]
pub unsafe fn base() -> usize {
    if TLS_OFF.load(Ordering::Relaxed) == 0 {
        return 0;
    }
    *slot()
}

/// Plant the thread-pointer base in the calling thread's slot. A plain
/// store, as Go's `save_g` is; `init` must have run.
#[inline]
pub unsafe fn set_base(b: usize) -> isize {
    *slot() = b;
    0
}

/// `locks += 1` on the calling thread's own `MStorage`. Three steps —
/// see the file header.
#[inline]
pub unsafe fn locks_inc<const OFF: usize>() {
    let p = (*slot() + OFF) as *mut u32;
    AtomicU32::from_ptr(p).fetch_add(1, Ordering::SeqCst);
}

/// `locks -= 1`, returning the pre-decrement value.
#[inline]
pub unsafe fn locks_dec<const OFF: usize>() -> u32 {
    let p = (*slot() + OFF) as *mut u32;
    AtomicU32::from_ptr(p).fetch_sub(1, Ordering::SeqCst)
}

// ─── the two AAPCS64 register reads ────────────────────────────────────
//
// Neither touches the thread pointer; both are identical to the
// Linux/arm64 file. Apple's ABI additionally *mandates* the frame
// pointer and the `[x29]`/`[x29+8]` frame record, where on Linux it is
// a `-C force-frame-pointers=yes` build flag.

/// Current frame-pointer value, for the `releasem` underflow walker.
#[inline]
pub unsafe fn frame_pointer() -> u64 {
    let fp: u64;
    core::arch::asm!("mov {}, x29", out(reg) fp, options(nomem, nostack));
    fp
}

/// Current stack-pointer value.
#[inline]
pub unsafe fn stack_pointer() -> usize {
    let sp: usize;
    core::arch::asm!(
        "mov {}, sp",
        out(reg) sp,
        options(nomem, nostack, preserves_flags),
    );
    sp
}
