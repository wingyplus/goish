// syscall — Go's `syscall` package, ported.
//
// One file per OS, mirroring Go's own `syscall/syscall_linux.go` /
// `syscall/syscall_darwin.go` split. This file is dispatch and nothing
// else: every name below is re-exported so `syscall::Write`,
// `syscall::SYS_WRITE`, `syscall::EAGAIN` and the other ~240 paths the
// tree already uses resolve exactly as they did when this was one
// 2137-line file.
//
// The arch dimension lives one level down — `zsysnum_linux_*.rs` and
// `asm_linux_*.rs` are `mod`-declared from `syscall_linux.rs`, because
// they are Linux's numbers and Linux's asm. Darwin has no `zsysnum`
// sibling at all: on libSystem there are no syscall numbers to table.

#[cfg(target_os = "linux")]
mod syscall_linux;
#[cfg(target_os = "linux")]
pub use syscall_linux::*;
