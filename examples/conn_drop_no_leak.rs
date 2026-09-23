// conn_drop_no_leak — verify Drop on Conn / Listener releases the
// kernel fd. We open and drop 1000 client+server pairs without
// calling Close explicitly; afterwards we count our own open fds
// (see `count_fds`) and assert the count hasn't grown unboundedly.
//
// Pre-M27h, every dropped Conn/Listener leaked one fd permanently.
// 1000 cycles would leave 2000+ fds open and eventually hit
// EMFILE. With Drop, we expect a stable fd count (≤ ~30 — the
// open-on-startup baseline plus any in-flight kept-alive conns).

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicI32, Ordering};
use goish::net;
use goish::runtime::netpoll;
use goish::{go, string, syscall};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

/// Count this process's open fds by asking the kernel about each
/// candidate: `fcntl(fd, F_GETFL)` succeeds on an open fd and fails
/// with EBADF on a closed one.
///
/// This used to list /proc/self/fd with raw `openat`/`getdents64`
/// numbers — x86_64's (257/217/3), so on arm64 Linux it issued the
/// wrong syscalls, and Darwin has neither /proc nor a raw syscall
/// entry point. The probe answers the same question through a wrapper
/// every target has, and is exact rather than a directory listing that
/// also counts its own fd.
///
/// The bound: fds are allocated lowest-first, so the leak this test
/// exists to catch (2000+ fds after 1000 cycles) lands well inside it.
fn count_fds() -> usize {
    const PROBE_LIMIT: i32 = 8192;
    let mut total = 0usize;
    let mut fd = 0;
    while fd < PROBE_LIMIT {
        if syscall::Fcntl(fd, syscall::F_GETFL, 0) >= 0 {
            total += 1;
        }
        fd += 1;
    }
    total
}

#[goish::main]
fn main() {
    let baseline = count_fds();
    let pd_total_opens_baseline = netpoll::total_opens_count();
    let pd_live_baseline = netpoll::live_count();

    // Spin up a long-lived listener to dial against. We wrap it in
    // an Arc so main can call Close() to break the accept loop on
    // shutdown — a clean exit lets bpftrace observability scripts
    // (scripts/bpftrace/netpoll_leak.bt) report a balanced delta.
    let (server_ln, err) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    check(err.IsNil(), b"server Listen failed\n");
    let port = server_ln.Addr().Port;
    static SERVER_PORT: AtomicI32 = AtomicI32::new(0);
    SERVER_PORT.store(port as i32, Ordering::Release);

    let server_ln = alloc::sync::Arc::new(server_ln);
    let server_ln_for_accept = server_ln.clone();

    // Server accept loop in a goroutine — accept and immediately drop.
    go!(move || {
        loop {
            let (conn, err) = server_ln_for_accept.Accept();
            if !err.IsNil() {
                return;
            }
            // Drop the conn immediately. With Drop, this should
            // release the fd back to the kernel.
            drop(conn);
        }
    });

    // Yield once so the server enters its accept loop.
    for _ in 0..10 {
        goish::runtime::sched::Gosched();
    }

    // Client side: 200 dial+drop cycles. Each cycle the kernel
    // assigns a new fd; without Drop, fds would accumulate.
    const ITERATIONS: usize = 200;
    for _ in 0..ITERATIONS {
        let p = SERVER_PORT.load(Ordering::Acquire) as u32;
        let mut addr_buf: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(24);
        addr_buf.extend_from_slice(b"127.0.0.1:");
        let mut tmp = [0u8; 6];
        let mut i = tmp.len();
        let mut n = p;
        while n > 0 {
            i -= 1;
            tmp[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
        addr_buf.extend_from_slice(&tmp[i..]);
        let addr = string::from_bytes(&addr_buf);

        let (conn, err) = net::Dial(string("tcp"), addr);
        if err.IsNil() {
            // Drop the conn without explicit Close.
            drop(conn);
        }
    }

    // Give the server time to drain the accepts (it's also dropping).
    for _ in 0..50 {
        goish::runtime::sched::Gosched();
    }

    let after = count_fds();

    // After 200 dial+drop cycles, fd count should be roughly
    // baseline + a small constant (server fd + epoll fd + eventfd
    // + a few in-flight). Threshold of baseline+30 is generous.
    if after > baseline + 30 {
        let msg = b"FD LEAK: count grew far beyond baseline\n";
        syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
        // Print numbers for diagnosis.
        let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        buf.extend_from_slice(b"baseline=");
        push_dec(&mut buf, baseline as u64);
        buf.extend_from_slice(b" after=");
        push_dec(&mut buf, after as u64);
        buf.extend_from_slice(b"\n");
        syscall::Write(syscall::STDERR, buf.as_ptr(), buf.len());
        syscall::Exit(1);
    }

    // Cleanly close the listener so the netpoll registration is
    // unregistered before exit — gives bpftrace a balanced report.
    let _ = server_ln.Close();
    // Yield so the accept goroutine notices the closed fd and exits,
    // dropping its Arc<Listener> clone (Drop is now idempotent so
    // this is harmless even though Close already ran).
    for _ in 0..20 {
        goish::runtime::sched::Gosched();
    }

    // PollDesc lifecycle report (M27k zero-leak model). `live` is
    // currently-allocated PollDesc instances; it should drop to zero
    // (the baseline) after all conns close. `opens` is the monotonic
    // count of registrations that happened during the test — useful
    // to confirm the test actually exercised the code. `recycled` is
    // slab-index reuse (memory reclaim, not slot reuse).
    let pd_total_opens_after = netpoll::total_opens_count();
    let pd_live_after = netpoll::live_count();
    let pd_opens_delta = pd_total_opens_after.saturating_sub(pd_total_opens_baseline);
    let pd_live_delta = (pd_live_after as isize) - (pd_live_baseline as isize);
    let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    buf.extend_from_slice(b"polldesc: live=");
    push_dec(&mut buf, pd_live_after as u64);
    buf.extend_from_slice(b" (");
    push_dec(&mut buf, netpoll::live_bytes() as u64);
    buf.extend_from_slice(b"B) opens+=");
    push_dec(&mut buf, pd_opens_delta as u64);
    buf.extend_from_slice(b" recycled=");
    push_dec(&mut buf, netpoll::recycled_count() as u64);
    buf.extend_from_slice(b" live_delta=");
    if pd_live_delta < 0 {
        buf.push(b'-');
        push_dec(&mut buf, (-pd_live_delta) as u64);
    } else {
        push_dec(&mut buf, pd_live_delta as u64);
    }
    buf.extend_from_slice(b"\n");
    syscall::Write(syscall::STDOUT, buf.as_ptr(), buf.len());

    // M27k invariant: live PollDescs should be at-or-below baseline
    // after every Conn/Listener has been dropped and the slab has
    // released its strong references. A non-trivial positive delta
    // means a PollDesc is being kept alive somewhere — a real leak.
    if pd_live_delta > 0 {
        let msg = b"PD LEAK: live PollDesc count grew during test\n";
        syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
        syscall::Exit(1);
    }

    let ok: &[u8] = b"conn_drop_no_leak: fd count stable across 200 dial+drop cycles\n";
    syscall::Write(syscall::STDOUT, ok.as_ptr(), ok.len());
    syscall::Exit(0);
}

fn push_dec(buf: &mut alloc::vec::Vec<u8>, mut n: u64) {
    if n == 0 {
        buf.push(b'0');
        return;
    }
    let mut tmp = [0u8; 20];
    let mut i = 0;
    while n > 0 {
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        buf.push(tmp[i]);
    }
}
