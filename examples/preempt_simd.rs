//! Forced SIGURG while every vector register and FP control register is live.
//! Each probe has no Rust calls between loading and storing the registers.
//! Other goroutines overwrite vector state while the interrupted G is parked.
#![no_std]
#![no_main]

use core::arch::{
    naked_asm,
    x86_64::{__cpuid, __cpuid_count, _xgetbv},
};
use core::sync::atomic::{AtomicU64, Ordering};
use goish::{
    go,
    runtime::{self, preempt},
    sync::WaitGroup,
    syscall,
};

const WORKERS: usize = 8;
const ROUNDS: usize = 32;
static COMPLETED: AtomicU64 = AtomicU64::new(0);

fn check(ok: bool, message: &str) {
    if !ok {
        syscall::Write(2, message.as_ptr(), message.len());
        syscall::Exit(1);
    }
}

// Probe arguments: input, output, pid, tid. Only caller-saved GPRs are used.
// The 16-byte local frame saves the caller's FP controls, which the SysV ABI
// requires us to restore before returning, even though the test changes them.

#[unsafe(naked)]
unsafe extern "C" fn probe_sse(_input: *const u64, _output: *mut u64, _pid: i32, _tid: i32) {
    naked_asm!(
        "sub rsp, 16",
        "stmxcsr [rsp]",
        "fnstcw [rsp + 4]",
        "ldmxcsr [rdi + 256]",
        "fldcw [rdi + 260]",
        "movdqu xmm0, [rdi + 0]",
        "movdqu xmm1, [rdi + 16]",
        "movdqu xmm2, [rdi + 32]",
        "movdqu xmm3, [rdi + 48]",
        "movdqu xmm4, [rdi + 64]",
        "movdqu xmm5, [rdi + 80]",
        "movdqu xmm6, [rdi + 96]",
        "movdqu xmm7, [rdi + 112]",
        "movdqu xmm8, [rdi + 128]",
        "movdqu xmm9, [rdi + 144]",
        "movdqu xmm10, [rdi + 160]",
        "movdqu xmm11, [rdi + 176]",
        "movdqu xmm12, [rdi + 192]",
        "movdqu xmm13, [rdi + 208]",
        "movdqu xmm14, [rdi + 224]",
        "movdqu xmm15, [rdi + 240]",
        "mov r9, rsi",
        "mov edi, edx",
        "mov esi, ecx",
        "mov edx, 23",
        "mov eax, 234",
        "syscall",
        ".globl goish_probe_sse_resume",
        "goish_probe_sse_resume:",
        "movdqu [r9 + 0], xmm0",
        "movdqu [r9 + 16], xmm1",
        "movdqu [r9 + 32], xmm2",
        "movdqu [r9 + 48], xmm3",
        "movdqu [r9 + 64], xmm4",
        "movdqu [r9 + 80], xmm5",
        "movdqu [r9 + 96], xmm6",
        "movdqu [r9 + 112], xmm7",
        "movdqu [r9 + 128], xmm8",
        "movdqu [r9 + 144], xmm9",
        "movdqu [r9 + 160], xmm10",
        "movdqu [r9 + 176], xmm11",
        "movdqu [r9 + 192], xmm12",
        "movdqu [r9 + 208], xmm13",
        "movdqu [r9 + 224], xmm14",
        "movdqu [r9 + 240], xmm15",
        "stmxcsr [r9 + 256]",
        "fnstcw [r9 + 260]",
        "ldmxcsr [rsp]",
        "fldcw [rsp + 4]",
        "add rsp, 16",
        "ret",
    )
}

#[unsafe(naked)]
unsafe extern "C" fn probe_avx(_input: *const u64, _output: *mut u64, _pid: i32, _tid: i32) {
    naked_asm!(
        "sub rsp, 16",
        "stmxcsr [rsp]",
        "fnstcw [rsp + 4]",
        "ldmxcsr [rdi + 512]",
        "fldcw [rdi + 516]",
        "vmovdqu ymm0, [rdi + 0]",
        "vmovdqu ymm1, [rdi + 32]",
        "vmovdqu ymm2, [rdi + 64]",
        "vmovdqu ymm3, [rdi + 96]",
        "vmovdqu ymm4, [rdi + 128]",
        "vmovdqu ymm5, [rdi + 160]",
        "vmovdqu ymm6, [rdi + 192]",
        "vmovdqu ymm7, [rdi + 224]",
        "vmovdqu ymm8, [rdi + 256]",
        "vmovdqu ymm9, [rdi + 288]",
        "vmovdqu ymm10, [rdi + 320]",
        "vmovdqu ymm11, [rdi + 352]",
        "vmovdqu ymm12, [rdi + 384]",
        "vmovdqu ymm13, [rdi + 416]",
        "vmovdqu ymm14, [rdi + 448]",
        "vmovdqu ymm15, [rdi + 480]",
        "mov r9, rsi",
        "mov edi, edx",
        "mov esi, ecx",
        "mov edx, 23",
        "mov eax, 234",
        "syscall",
        ".globl goish_probe_avx_resume",
        "goish_probe_avx_resume:",
        "vmovdqu [r9 + 0], ymm0",
        "vmovdqu [r9 + 32], ymm1",
        "vmovdqu [r9 + 64], ymm2",
        "vmovdqu [r9 + 96], ymm3",
        "vmovdqu [r9 + 128], ymm4",
        "vmovdqu [r9 + 160], ymm5",
        "vmovdqu [r9 + 192], ymm6",
        "vmovdqu [r9 + 224], ymm7",
        "vmovdqu [r9 + 256], ymm8",
        "vmovdqu [r9 + 288], ymm9",
        "vmovdqu [r9 + 320], ymm10",
        "vmovdqu [r9 + 352], ymm11",
        "vmovdqu [r9 + 384], ymm12",
        "vmovdqu [r9 + 416], ymm13",
        "vmovdqu [r9 + 448], ymm14",
        "vmovdqu [r9 + 480], ymm15",
        "stmxcsr [r9 + 512]",
        "fnstcw [r9 + 516]",
        "ldmxcsr [rsp]",
        "fldcw [rsp + 4]",
        "vzeroupper",
        "add rsp, 16",
        "ret",
    )
}

#[unsafe(naked)]
unsafe extern "C" fn probe_avx512(_input: *const u64, _output: *mut u64, _pid: i32, _tid: i32) {
    naked_asm!(
        "sub rsp, 16",
        "stmxcsr [rsp]",
        "fnstcw [rsp + 4]",
        "ldmxcsr [rdi + 2112]",
        "fldcw [rdi + 2116]",
        "vmovdqu64 zmm0, [rdi + 0]",
        "vmovdqu64 zmm1, [rdi + 64]",
        "vmovdqu64 zmm2, [rdi + 128]",
        "vmovdqu64 zmm3, [rdi + 192]",
        "vmovdqu64 zmm4, [rdi + 256]",
        "vmovdqu64 zmm5, [rdi + 320]",
        "vmovdqu64 zmm6, [rdi + 384]",
        "vmovdqu64 zmm7, [rdi + 448]",
        "vmovdqu64 zmm8, [rdi + 512]",
        "vmovdqu64 zmm9, [rdi + 576]",
        "vmovdqu64 zmm10, [rdi + 640]",
        "vmovdqu64 zmm11, [rdi + 704]",
        "vmovdqu64 zmm12, [rdi + 768]",
        "vmovdqu64 zmm13, [rdi + 832]",
        "vmovdqu64 zmm14, [rdi + 896]",
        "vmovdqu64 zmm15, [rdi + 960]",
        "vmovdqu64 zmm16, [rdi + 1024]",
        "vmovdqu64 zmm17, [rdi + 1088]",
        "vmovdqu64 zmm18, [rdi + 1152]",
        "vmovdqu64 zmm19, [rdi + 1216]",
        "vmovdqu64 zmm20, [rdi + 1280]",
        "vmovdqu64 zmm21, [rdi + 1344]",
        "vmovdqu64 zmm22, [rdi + 1408]",
        "vmovdqu64 zmm23, [rdi + 1472]",
        "vmovdqu64 zmm24, [rdi + 1536]",
        "vmovdqu64 zmm25, [rdi + 1600]",
        "vmovdqu64 zmm26, [rdi + 1664]",
        "vmovdqu64 zmm27, [rdi + 1728]",
        "vmovdqu64 zmm28, [rdi + 1792]",
        "vmovdqu64 zmm29, [rdi + 1856]",
        "vmovdqu64 zmm30, [rdi + 1920]",
        "vmovdqu64 zmm31, [rdi + 1984]",
        "kmovq k0, [rdi + 2048]",
        "kmovq k1, [rdi + 2056]",
        "kmovq k2, [rdi + 2064]",
        "kmovq k3, [rdi + 2072]",
        "kmovq k4, [rdi + 2080]",
        "kmovq k5, [rdi + 2088]",
        "kmovq k6, [rdi + 2096]",
        "kmovq k7, [rdi + 2104]",
        "mov r9, rsi",
        "mov edi, edx",
        "mov esi, ecx",
        "mov edx, 23",
        "mov eax, 234",
        "syscall",
        ".globl goish_probe_avx512_resume",
        "goish_probe_avx512_resume:",
        "vmovdqu64 [r9 + 0], zmm0",
        "vmovdqu64 [r9 + 64], zmm1",
        "vmovdqu64 [r9 + 128], zmm2",
        "vmovdqu64 [r9 + 192], zmm3",
        "vmovdqu64 [r9 + 256], zmm4",
        "vmovdqu64 [r9 + 320], zmm5",
        "vmovdqu64 [r9 + 384], zmm6",
        "vmovdqu64 [r9 + 448], zmm7",
        "vmovdqu64 [r9 + 512], zmm8",
        "vmovdqu64 [r9 + 576], zmm9",
        "vmovdqu64 [r9 + 640], zmm10",
        "vmovdqu64 [r9 + 704], zmm11",
        "vmovdqu64 [r9 + 768], zmm12",
        "vmovdqu64 [r9 + 832], zmm13",
        "vmovdqu64 [r9 + 896], zmm14",
        "vmovdqu64 [r9 + 960], zmm15",
        "vmovdqu64 [r9 + 1024], zmm16",
        "vmovdqu64 [r9 + 1088], zmm17",
        "vmovdqu64 [r9 + 1152], zmm18",
        "vmovdqu64 [r9 + 1216], zmm19",
        "vmovdqu64 [r9 + 1280], zmm20",
        "vmovdqu64 [r9 + 1344], zmm21",
        "vmovdqu64 [r9 + 1408], zmm22",
        "vmovdqu64 [r9 + 1472], zmm23",
        "vmovdqu64 [r9 + 1536], zmm24",
        "vmovdqu64 [r9 + 1600], zmm25",
        "vmovdqu64 [r9 + 1664], zmm26",
        "vmovdqu64 [r9 + 1728], zmm27",
        "vmovdqu64 [r9 + 1792], zmm28",
        "vmovdqu64 [r9 + 1856], zmm29",
        "vmovdqu64 [r9 + 1920], zmm30",
        "vmovdqu64 [r9 + 1984], zmm31",
        "kmovq [r9 + 2048], k0",
        "kmovq [r9 + 2056], k1",
        "kmovq [r9 + 2064], k2",
        "kmovq [r9 + 2072], k3",
        "kmovq [r9 + 2080], k4",
        "kmovq [r9 + 2088], k5",
        "kmovq [r9 + 2096], k6",
        "kmovq [r9 + 2104], k7",
        "stmxcsr [r9 + 2112]",
        "fnstcw [r9 + 2116]",
        "ldmxcsr [rsp]",
        "fldcw [rsp + 4]",
        "vzeroupper",
        "add rsp, 16",
        "ret",
    )
}

// Run only the signal syscall at a synthetic SP within this G's allocation.
// No memory is touched there except by an accepted preemption. The handler
// itself uses the alternate signal stack, including when SP is below base.
#[unsafe(naked)]
unsafe extern "C" fn probe_stack(_sp: usize, _pid: i32, _tid: i32) {
    naked_asm!(
        "mov r8, rsp",
        "mov rsp, rdi",
        "mov edi, esi",
        "mov esi, edx",
        "mov edx, 23",
        "mov eax, 234",
        "syscall",
        ".globl goish_probe_stack_resume",
        "goish_probe_stack_resume:",
        "mov rsp, r8",
        "ret",
    )
}

fn stack_boundaries() {
    runtime::GOMAXPROCS(1);
    go!(|| {
        let g = runtime::sched::current_g().unwrap();
        let base = unsafe { g.as_ref().stack.base() };
        let budget = preempt::async_preempt_stack();
        check(
            budget >= preempt::ASYNC_PREEMPT_STACK,
            "preempt_simd: invalid stack budget\n",
        );
        for sp in [base - 1, base, base + budget - 1] {
            let before = preempt::skip_breakdown().5;
            unsafe {
                probe_stack(sp, syscall::Getpid(), syscall::Gettid());
            }
            check(
                preempt::skip_breakdown().5 > before,
                "preempt_simd: insufficient headroom was not rejected\n",
            );
        }
        // Exercise the exact lower bound and every possible alignment offset.
        for offset in 0..64 {
            let before = preempt::injections();
            unsafe {
                probe_stack(base + budget + offset, syscall::Getpid(), syscall::Gettid());
            }
            check(
                preempt::injections() > before,
                "preempt_simd: sufficient headroom was rejected\n",
            );
        }
    });
    runtime::sched::schedule();
}

unsafe extern "C" {
    static goish_probe_sse_resume: u8;
    static goish_probe_avx_resume: u8;
    static goish_probe_avx512_resume: u8;
}

fn exercise(kind: usize, identity: usize) {
    let words = [32, 64, 264][kind];
    let mut input = [0u64; 265];
    let mut output = [0u64; 265];
    for round in 0..ROUNDS {
        for (i, value) in input[..words].iter_mut().enumerate() {
            *value = 0x1122_3344_5566_7788u64
                .wrapping_add(u64::try_from(identity * 4096 + round * 128 + i).unwrap());
        }
        // Alternate valid rounding controls; mask all FP exceptions.
        let alternate = (identity + round) % 2 != 0;
        let mxcsr = if alternate { 0x3f80u64 } else { 0x1f80 };
        let fcw = if alternate { 0x077fu64 } else { 0x037f };
        input[words] = mxcsr | (fcw << 32);
        output.fill(0);
        let tid = syscall::Gettid();
        let pid = syscall::Getpid();
        unsafe {
            match kind {
                0 => probe_sse(input.as_ptr(), output.as_mut_ptr(), pid, tid),
                1 => probe_avx(input.as_ptr(), output.as_mut_ptr(), pid, tid),
                _ => probe_avx512(input.as_ptr(), output.as_mut_ptr(), pid, tid),
            }
        }
        check(
            input[..=words] == output[..=words],
            "preempt_simd: register corruption\n",
        );
    }
    COMPLETED.fetch_add(1, Ordering::Relaxed);
}

fn has_probe_injection(kind: usize) -> bool {
    let pc = match kind {
        0 => core::ptr::addr_of!(goish_probe_sse_resume).addr(),
        1 => core::ptr::addr_of!(goish_probe_avx_resume).addr(),
        _ => core::ptr::addr_of!(goish_probe_avx512_resume).addr(),
    };
    let mut pcs = [0; 32];
    let n = preempt::snapshot_injection_pcs(&mut pcs);
    pcs[..n].contains(&u64::try_from(pc).unwrap())
}

fn run(kind: usize, threads: i64) {
    runtime::GOMAXPROCS(threads);
    let before = preempt::injections();
    let completed = COMPLETED.load(Ordering::Relaxed);
    static WG: WaitGroup = WaitGroup::new();
    WG.Add(i64::try_from(WORKERS).unwrap());
    for i in 0..WORKERS {
        go!(move || {
            exercise(kind, i);
            WG.Done();
        });
    }
    go!(|| {
        WG.Wait();
    });
    runtime::sched::schedule();
    check(
        COMPLETED.load(Ordering::Relaxed) == completed + u64::try_from(WORKERS).unwrap(),
        "preempt_simd: incomplete probes\n",
    );
    check(
        preempt::injections() >= before + u64::try_from(WORKERS * ROUNDS).unwrap(),
        "preempt_simd: missing forced preemptions\n",
    );
    check(
        has_probe_injection(kind),
        "preempt_simd: did not interrupt a live-register probe\n",
    );
}

#[goish::main]
fn main() {
    stack_boundaries();
    let cpu = __cpuid(1);
    let avx =
        cpu.ecx & (1 << 27) != 0 && cpu.ecx & (1 << 28) != 0 && unsafe { _xgetbv(0) } & 6 == 6;
    let features = __cpuid_count(7, 0);
    let avx512 = avx
        && features.ebx & (1 << 16) != 0
        && features.ebx & (1 << 30) != 0
        && unsafe { _xgetbv(0) } & 0xe6 == 0xe6;
    for threads in [1, 4] {
        run(0, threads);
        if avx {
            run(1, threads);
        }
        if avx512 {
            run(2, threads);
        }
    }
    for message in [
        "preempt_simd: SSE passed\n",
        if avx {
            "preempt_simd: AVX passed\n"
        } else {
            "preempt_simd: AVX unavailable\n"
        },
        if avx512 {
            "preempt_simd: AVX-512 passed\n"
        } else {
            "preempt_simd: AVX-512 unavailable\n"
        },
    ] {
        syscall::Write(1, message.as_ptr(), message.len());
    }
}
