// runtime::symbolize::macho — the Mach-O container, for aarch64-apple-darwin.
//
// The ELF path reads everything out of one file, `/proc/self/exe`,
// because on Linux the linked executable carries `.symtab` and every
// `.debug_*` section. A Mach-O executable does not: ld64 never copies
// DWARF into the final image. It leaves a *debug map* instead — N_OSO
// stabs naming each object file the DWARF is still in — and those object
// files are gone by the time an example runs (rustc deletes a binary
// crate's own `.o`s after linking, and CI builds with
// CARGO_INCREMENTAL=0, so there is no incremental cache to find them in
// either). The only durable home for the DWARF is a dSYM bundle, which
// `.cargo/config.toml` asks cargo to produce (`split-debuginfo=packed`).
//
// So the two halves of a `SymInfo` come from two places:
//
//   * **Function names** come from the *loaded image*: `__LINKEDIT` is
//     mapped, and `LC_SYMTAB` says where in it the `nlist_64` array and
//     the string table sit. This needs no file I/O and no dSYM, so names
//     resolve for any unstripped build — including one whose dSYM was
//     deleted or never made.
//   * **file:line** comes from `<exe>.dSYM/Contents/Resources/DWARF/*`,
//     a Mach-O file whose `__DWARF` segment carries `__debug_line`,
//     `__debug_info`, `__debug_abbrev` and `__debug_str`. Those feed the
//     same container-independent decoders (`info.rs`, `line.rs`) the ELF
//     path uses. A dSYM whose `LC_UUID` differs from the image's belongs
//     to some other build of the executable and is ignored: stale line
//     numbers are worse than none.
//
// Both tables are keyed by **link-time** (unslid) addresses — `n_value`
// and DWARF addresses are both what ld64 assigned. The runtime PC is
// slid by ASLR, so `Tables::slide` records the difference and
// `symbolize()` subtracts it before either lookup.
//
// Layouts are `<mach-o/loader.h>` and `<mach-o/nlist.h>`; every struct
// is read field-by-field at a byte offset rather than cast, so nothing
// here depends on alignment of the mapped bytes.

use alloc::vec::Vec;

use super::symtab::{SymRange, SymTable};
use super::Tables;
use crate::syscall;

const MH_MAGIC_64: u32 = 0xfeed_facf;
const MACH_HEADER_64_SIZE: usize = 32;

const LC_SYMTAB: u32 = 0x2;
const LC_SEGMENT_64: u32 = 0x19;
const LC_UUID: u32 = 0x1b;

/// `segment_command_64` is 72 bytes; its `section_64`s follow it.
const SEGMENT_COMMAND_64_SIZE: usize = 72;
const SECTION_64_SIZE: usize = 80;

/// `section_64.flags` attribute bits marking a section as code.
const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;

/// `nlist_64` is 16 bytes: n_strx u32, n_type u8, n_sect u8, n_desc
/// u16, n_value u64.
const NLIST_64_SIZE: usize = 16;
const N_STAB: u8 = 0xe0;
const N_TYPE: u8 = 0x0e;
const N_SECT: u8 = 0x0e;
const N_EXT: u8 = 0x01;

#[inline]
fn rd_u32(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

#[inline]
fn rd_u64(b: &[u8], off: usize) -> Option<u64> {
    let s = b.get(off..off + 8)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Some(u64::from_le_bytes(a))
}

/// A 16-byte, NUL-padded Mach-O name field compared against `want`.
#[inline]
fn name16_eq(field: &[u8], want: &[u8]) -> bool {
    let n = field.iter().position(|&c| c == 0).unwrap_or(field.len());
    &field[..n] == want
}

struct Segment {
    name: [u8; 16],
    vmaddr: u64,
    fileoff: u64,
}

struct Section {
    segname: [u8; 16],
    sectname: [u8; 16],
    addr: u64,
    size: u64,
    offset: u32,
    flags: u32,
}

/// What the load commands of one Mach-O 64 header say. `bytes` spans
/// the header and its load commands (`sizeofcmds`) at least.
struct LoadCommands {
    segments: Vec<Segment>,
    /// Every section in load-command order — `nlist_64.n_sect` is a
    /// 1-based index into exactly this sequence.
    sections: Vec<Section>,
    /// `(symoff, nsyms, stroff, strsize)` from `LC_SYMTAB`.
    symtab: Option<(u32, u32, u32, u32)>,
    uuid: Option<[u8; 16]>,
}

fn parse_load_commands(bytes: &[u8]) -> Option<LoadCommands> {
    if rd_u32(bytes, 0)? != MH_MAGIC_64 {
        return None;
    }
    let ncmds = rd_u32(bytes, 16)? as usize;
    let sizeofcmds = rd_u32(bytes, 20)? as usize;
    let end = MACH_HEADER_64_SIZE.checked_add(sizeofcmds)?;
    if end > bytes.len() {
        return None;
    }
    let mut out = LoadCommands {
        segments: Vec::new(),
        sections: Vec::new(),
        symtab: None,
        uuid: None,
    };
    let mut off = MACH_HEADER_64_SIZE;
    for _ in 0..ncmds {
        let cmd = rd_u32(bytes, off)?;
        let cmdsize = rd_u32(bytes, off + 4)? as usize;
        if cmdsize < 8 || off + cmdsize > end {
            return None;
        }
        match cmd {
            LC_SEGMENT_64 => {
                let mut name = [0u8; 16];
                name.copy_from_slice(bytes.get(off + 8..off + 24)?);
                out.segments.push(Segment {
                    name,
                    vmaddr: rd_u64(bytes, off + 24)?,
                    fileoff: rd_u64(bytes, off + 40)?,
                });
                let nsects = rd_u32(bytes, off + 64)? as usize;
                let mut s = off + SEGMENT_COMMAND_64_SIZE;
                for _ in 0..nsects {
                    if s + SECTION_64_SIZE > off + cmdsize {
                        return None;
                    }
                    let mut sectname = [0u8; 16];
                    sectname.copy_from_slice(&bytes[s..s + 16]);
                    let mut segname = [0u8; 16];
                    segname.copy_from_slice(&bytes[s + 16..s + 32]);
                    out.sections.push(Section {
                        segname,
                        sectname,
                        addr: rd_u64(bytes, s + 32)?,
                        size: rd_u64(bytes, s + 40)?,
                        offset: rd_u32(bytes, s + 48)?,
                        flags: rd_u32(bytes, s + 64)?,
                    });
                    s += SECTION_64_SIZE;
                }
            }
            LC_SYMTAB => {
                out.symtab = Some((
                    rd_u32(bytes, off + 8)?,
                    rd_u32(bytes, off + 12)?,
                    rd_u32(bytes, off + 16)?,
                    rd_u32(bytes, off + 20)?,
                ));
            }
            LC_UUID => {
                let mut u = [0u8; 16];
                u.copy_from_slice(bytes.get(off + 8..off + 24)?);
                out.uuid = Some(u);
            }
            _ => {}
        }
        off += cmdsize;
    }
    Some(out)
}

/// Build the tables for the running executable. `None` only when the
/// image itself cannot be read; a missing or mismatched dSYM still
/// yields names, with an empty line table.
pub(super) fn load() -> Option<Tables> {
    // The mapped header. Its load commands follow it in the same
    // mapping (`__TEXT` starts at file offset 0), so reading
    // `32 + sizeofcmds` bytes from it is in bounds.
    let mh = crate::sys::sys_mh_execute_header();
    let sizeofcmds = unsafe {
        let h = core::slice::from_raw_parts(mh, MACH_HEADER_64_SIZE);
        rd_u32(h, 20)? as usize
    };
    let hdr: &'static [u8] =
        unsafe { core::slice::from_raw_parts(mh, MACH_HEADER_64_SIZE + sizeofcmds) };
    let lc = parse_load_commands(hdr)?;

    // Slide = where `__TEXT` is minus where ld64 put it. The header IS
    // the first byte of `__TEXT`.
    let text_seg = lc.segments.iter().find(|s| name16_eq(&s.name, b"__TEXT"))?;
    let slide = (mh as u64).wrapping_sub(text_seg.vmaddr);

    // `__LINKEDIT` is mapped at `vmaddr + slide`, and holds the file
    // range starting at `fileoff`; LC_SYMTAB's offsets are file
    // offsets, so rebase them onto the mapping.
    let linkedit = lc.segments.iter().find(|s| name16_eq(&s.name, b"__LINKEDIT"))?;
    let (symoff, nsyms, stroff, strsize) = lc.symtab?;
    let le_base = linkedit.vmaddr.wrapping_add(slide);
    let sym_addr = le_base.wrapping_add((symoff as u64).wrapping_sub(linkedit.fileoff));
    let str_addr = le_base.wrapping_add((stroff as u64).wrapping_sub(linkedit.fileoff));
    let nlists: &'static [u8] = unsafe {
        core::slice::from_raw_parts(sym_addr as *const u8, nsyms as usize * NLIST_64_SIZE)
    };
    let strtab: &'static [u8] =
        unsafe { core::slice::from_raw_parts(str_addr as *const u8, strsize as usize) };

    let symtab = build_symtab(nlists, strtab, &lc.sections);
    let lines = match lc.uuid {
        Some(uuid) => load_dsym_lines(&uuid),
        None => None,
    }
    .unwrap_or(super::line::Programs {
        rows: Vec::new(),
        programs: Vec::new(),
    });

    Some(Tables {
        symtab,
        strtab,
        lines,
        slide,
    })
}

/// Function ranges from the `nlist_64` array.
///
/// Mach-O symbols carry no size, so a function ends where the next one
/// starts — clamped to the end of its own section, so the last function
/// in `__text` does not swallow whatever section follows (goish places
/// its runtime trampolines in a separate `__TEXT,__goish_rt_text`).
///
/// Kept: `N_SECT` definitions in a code section whose name begins with
/// `_` — C-level symbols, external or local. Dropped: debug-map stabs
/// (`N_STAB`), undefined and absolute symbols, and assembler-local
/// labels such as `ltmp0` and `.Lfunc_end…`, which would otherwise split
/// a function in two at a label that is not an entry point.
fn build_symtab(nlists: &[u8], strtab: &[u8], sections: &[Section]) -> SymTable {
    // (start, section_end, name_off, is_ext)
    let mut raw: Vec<(u64, u64, u32, bool)> = Vec::new();
    let n = nlists.len() / NLIST_64_SIZE;
    for i in 0..n {
        let e = i * NLIST_64_SIZE;
        let n_strx = match rd_u32(nlists, e) {
            Some(v) => v,
            None => break,
        };
        let n_type = nlists[e + 4];
        let n_sect = nlists[e + 5];
        let n_value = match rd_u64(nlists, e + 8) {
            Some(v) => v,
            None => break,
        };
        if n_type & N_STAB != 0 || n_type & N_TYPE != N_SECT || n_sect == 0 {
            continue;
        }
        let sect = match sections.get(n_sect as usize - 1) {
            Some(s) => s,
            None => continue,
        };
        if sect.flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS) == 0 {
            continue;
        }
        if strtab.get(n_strx as usize) != Some(&b'_') {
            continue;
        }
        // Mach-O prefixes every C-level name with one `_`: the Rust
        // symbol `_RNv…` is stored as `__RNv…`. Point past it so the
        // demanglers see what the ELF strtab would have given them.
        raw.push((n_value, sect.addr + sect.size, n_strx + 1, n_type & N_EXT != 0));
    }
    // Aliases share an address; keep one per start, the external one
    // when there is a choice (it is the name a user wrote or exported).
    raw.sort_by(|a, b| a.0.cmp(&b.0).then(b.3.cmp(&a.3)));
    raw.dedup_by_key(|r| r.0);

    let mut ranges: Vec<SymRange> = Vec::with_capacity(raw.len());
    for i in 0..raw.len() {
        let (start, sect_end, name_off, _) = raw[i];
        let mut end = sect_end;
        if let Some(next) = raw.get(i + 1) {
            if next.0 < end {
                end = next.0;
            }
        }
        if end <= start {
            continue;
        }
        ranges.push(SymRange {
            start,
            end,
            name_off,
        });
    }
    SymTable { ranges }
}

/// Open the dSYM beside the executable, check its UUID against
/// `want_uuid`, and decode its line programs.
///
/// Cargo's uplift leaves `examples/<name>.dSYM` as a symlink to
/// `<name>-<hash>.dSYM`, whose DWARF file is named after the hashed
/// binary — so the file inside is found by listing the directory rather
/// than by constructing a name from the executable's. Every entry is
/// tried; the UUID picks the right one.
fn load_dsym_lines(want_uuid: &[u8; 16]) -> Option<super::line::Programs> {
    let mut exe = [0u8; 1024];
    let n = unsafe { crate::sys::sys_executable_path(&mut exe) };
    if n <= 0 {
        return None;
    }
    let mut dir: Vec<u8> = Vec::with_capacity(n as usize + 64);
    dir.extend_from_slice(&exe[..n as usize]);
    dir.extend_from_slice(b".dSYM/Contents/Resources/DWARF");

    for name in list_dir(&dir) {
        let mut path = dir.clone();
        path.push(b'/');
        path.extend_from_slice(&name);
        let bytes = match map_file(&mut path) {
            Some(b) => b,
            None => continue,
        };
        let lc = match parse_load_commands(bytes) {
            Some(l) => l,
            None => continue,
        };
        if lc.uuid.as_ref() != Some(want_uuid) {
            continue;
        }
        return Some(lines_from_dwarf(bytes, &lc.sections));
    }
    None
}

fn lines_from_dwarf(bytes: &'static [u8], sections: &[Section]) -> super::line::Programs {
    let find = |want: &[u8]| -> &'static [u8] {
        for s in sections {
            if !name16_eq(&s.segname, b"__DWARF") || !name16_eq(&s.sectname, want) {
                continue;
            }
            let lo = s.offset as usize;
            let hi = match lo.checked_add(s.size as usize) {
                Some(h) => h,
                None => return &[],
            };
            return bytes.get(lo..hi).unwrap_or(&[]);
        }
        &[]
    };
    super::build_lines(
        find(b"__debug_info"),
        find(b"__debug_abbrev"),
        find(b"__debug_str"),
        find(b"__debug_line"),
    )
}

/// mmap `path` (NUL appended here) read-only for the life of the
/// process. The dSYM's DWARF is only ever borrowed from, like the ELF
/// path's `/proc/self/exe` mapping, and is never unmapped.
fn map_file(path: &mut Vec<u8>) -> Option<&'static [u8]> {
    path.push(0);
    let fd = syscall::Open(path.as_ptr(), syscall::O_RDONLY | syscall::O_CLOEXEC, 0);
    path.pop();
    if fd < 0 {
        return None;
    }
    let mut st = syscall::Stat_t::default();
    if syscall::Fstat(fd, &mut st) != 0 || st.st_size <= 0 {
        syscall::Close(fd);
        return None;
    }
    let size = st.st_size as usize;
    let base = syscall::Mmap(
        core::ptr::null_mut(),
        size,
        syscall::PROT_READ,
        syscall::MAP_PRIVATE,
        fd,
        0,
    );
    syscall::Close(fd);
    if (base as isize) <= 0 {
        return None;
    }
    Some(unsafe { core::slice::from_raw_parts(base, size) })
}

/// Names in directory `path`, minus `.` and `..`. Empty on any error.
/// `Getdents64` hands back Linux `dirent64` records on this target too
/// (`syscall_darwin.rs` translates `getdirentries64`): d_ino u64,
/// d_off i64, d_reclen u16, d_type u8, then the NUL-terminated name.
fn list_dir(path: &[u8]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut p: Vec<u8> = Vec::with_capacity(path.len() + 1);
    p.extend_from_slice(path);
    p.push(0);
    let fd = syscall::Open(
        p.as_ptr(),
        syscall::O_RDONLY | syscall::O_DIRECTORY | syscall::O_CLOEXEC,
        0,
    );
    if fd < 0 {
        return out;
    }
    let mut buf = [0u8; 4096];
    loop {
        let n = syscall::Getdents64(fd, buf.as_mut_ptr(), buf.len());
        if n <= 0 {
            break;
        }
        let n = n as usize;
        let mut i = 0usize;
        while i + 19 < n {
            let reclen = u16::from_le_bytes([buf[i + 16], buf[i + 17]]) as usize;
            if reclen == 0 || i + reclen > n {
                break;
            }
            let name = &buf[i + 19..i + reclen];
            let len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
            let name = &name[..len];
            if name != b"." && name != b".." && !name.is_empty() {
                out.push(name.to_vec());
            }
            i += reclen;
        }
    }
    syscall::Close(fd);
    out
}
