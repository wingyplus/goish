#!/usr/bin/env python3
"""cross_lld.py - link goish's Linux ELF from a non-Linux host.

    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=scripts/cross_lld.py \
        cargo build --target aarch64-unknown-linux-gnu --example hello

Why this exists
---------------
The project's CI hosts are Linux and use the system `cc` as the linker
driver. A macOS development host has no such driver for a Linux target,
and the usual stand-ins do not work here:

  * Apple's `ld` cannot produce ELF at all.
  * `zig cc` refuses this exact flag set. `-target x86_64-linux-gnu`
    rejects `-static`; `-target x86_64-linux-musl` rejects
    `--no-dynamic-linker` while sub-compiling a libc goish never links.

`rust-lld` ships inside the rustup toolchain and does produce ELF, but
rustc invokes the linker with cc-style arguments. This translates:
`-Wl,` prefixes are unwrapped and the driver-only flags are dropped —
they are all no-ops for a direct linker invocation, because goish
already passes `-static` and `--no-dynamic-linker` explicitly and links
neither startup files nor a default library.

This is a development convenience for cross-checking a Linux build from
a Mac. It is not on the CI path and nothing in the build requires it.
"""
import os, subprocess, sys

# `-m` is not inferable from the object files, so the target is selected
# by which env var cargo used to reach us. Keep this table in step with
# the targets `.cargo/config.toml` declares.
EMULATION = {
    "aarch64-unknown-linux-gnu": "aarch64linux",
    "x86_64-unknown-linux-gnu": "elf_x86_64",
}

# cc-driver flags with no ld equivalent. Each is already implied by an
# explicit flag rustc passes through, or is meaningless to the linker.
DROP = {"-m64", "-nodefaultlibs", "-nostartfiles", "-no-pie", "-pie", "-fuse-ld=lld"}

# Drop the jobserver handshake, for every child this process spawns.
#
# cargo advertises a jobserver through CARGO_MAKEFLAGS as inheritable file
# descriptors. This process sits in between and does not pass them on
# (subprocess closes fds > 2), so any child that looks for fd 3 fails and
# prints
#
#     warning: failed to connect to jobserver from environment variable
#     note: the build environment is likely misconfigured
#
# which rustc then surfaces on every link as `linker stderr: ...`.
# Nothing is actually misconfigured. Note the culprits are the `rustc`
# probes in lld() below as much as lld itself — which is why this has to
# happen at import time rather than at the call, and why stripping it
# only for the lld child did not help.
for _k in ("CARGO_MAKEFLAGS", "MAKEFLAGS", "MFLAGS"):
    os.environ.pop(_k, None)


def rustc():
    """The rustc that actually owns the cross targets.

    `rustc` on PATH is not necessarily the rustup shim. A Homebrew rust
    installs to /opt/homebrew/bin, comes first on PATH, ships only the
    host std, and does not ship rust-lld at all — so resolving through it
    yields a sysroot with no linker in it. Ask rustup first; fall back to
    PATH only when rustup is absent.
    """
    try:
        return subprocess.check_output(
            ["rustup", "which", "rustc"], text=True,
            stderr=subprocess.DEVNULL).strip()
    except Exception:
        return "rustc"


def lld():
    """rust-lld from the active toolchain's own sysroot."""
    rc = rustc()
    sysroot = subprocess.check_output([rc, "--print", "sysroot"], text=True).strip()
    host = subprocess.check_output([rc, "-vV"], text=True)
    host = [l.split(": ", 1)[1] for l in host.splitlines() if l.startswith("host: ")][0]
    p = os.path.join(sysroot, "lib", "rustlib", host, "bin", "rust-lld")
    if not os.path.exists(p):
        sys.exit("cross_lld: no rust-lld at %s\n"
                 "  rustc in use: %s\n"
                 "  A Homebrew rust has no rust-lld; install rustup, or point\n"
                 "  $PATH at ~/.cargo/bin ahead of /opt/homebrew/bin." % (p, rc))
    return p


def main(argv):
    target = os.environ.get("GOISH_CROSS_TARGET")
    if not target:
        # Inferred from the object paths cargo hands us, which live under
        # target/<tuple>/.
        for a in argv:
            for t in EMULATION:
                if "/%s/" % t in a:
                    target = t
                    break
            if target:
                break
    if target not in EMULATION:
        sys.exit("cross_lld: set GOISH_CROSS_TARGET to one of %s"
                 % ", ".join(sorted(EMULATION)))

    out = ["-flavor", "gnu", "-m", EMULATION[target]]
    for a in argv:
        if a in DROP:
            continue
        if a.startswith("-Wl,"):
            out.extend(a[4:].split(","))
        else:
            out.append(a)

    return subprocess.call([lld()] + out)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
