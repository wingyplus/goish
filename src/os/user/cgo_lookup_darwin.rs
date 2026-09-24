// go: file os/user/cgo_lookup_unix.go decls: lookupUser, lookupUserId, lookupGroup, lookupGroupId
//
// os/user on darwin/arm64 — the libc lookups, not the /etc/passwd reader.
//
// macOS keeps accounts in Directory Services; /etc/passwd lists only a
// handful of system users and never the people who log in, so the pure
// reader in `lookup_unix.rs` answers "unknown userid 502" for the
// current user. Go's default darwin build uses cgo and takes this path
// (`os/user/cgo_lookup_unix.go`), and goish already links libSystem, so
// the same four `get*_r` calls are one extern block away. That also
// makes the answers Go's: root's home is /var/root here, not /root.
//
// Deviation: Go grows the buffer on ERANGE in `retryWithBuffer`
// (cgo_lookup_unix.go:170-190). One 16 KiB buffer is used here — larger
// than `sysconf(_SC_GETPW_R_SIZE_MAX)` on macOS — and ERANGE is reported
// as an error rather than retried.
#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;

use crate::errors::{self, error};
use crate::gostring::string;
use crate::strconv;
use crate::strings;

use super::user::{Group, User, UnknownGroupError, UnknownGroupIdError, UnknownUserError, UnknownUserIdError};

/// `struct passwd` — 72 bytes, measured against `<pwd.h>`.
#[repr(C)]
struct Passwd {
    pw_name: *const u8,
    pw_passwd: *const u8,
    pw_uid: u32,
    pw_gid: u32,
    pw_change: i64,
    pw_class: *const u8,
    pw_gecos: *const u8,
    pw_dir: *const u8,
    pw_shell: *const u8,
    pw_expire: i64,
}

/// `struct group` — 32 bytes, measured against `<grp.h>`.
#[repr(C)]
struct CGroup {
    gr_name: *const u8,
    gr_passwd: *const u8,
    gr_gid: u32,
    gr_mem: *const *const u8,
}

#[link(name = "System")]
extern "C" {
    fn getpwnam_r(name: *const u8, pwd: *mut Passwd, buf: *mut u8, n: usize, res: *mut *mut Passwd) -> i32;
    fn getpwuid_r(uid: u32, pwd: *mut Passwd, buf: *mut u8, n: usize, res: *mut *mut Passwd) -> i32;
    fn getgrnam_r(name: *const u8, grp: *mut CGroup, buf: *mut u8, n: usize, res: *mut *mut CGroup) -> i32;
    fn getgrgid_r(gid: u32, grp: *mut CGroup, buf: *mut u8, n: usize, res: *mut *mut CGroup) -> i32;
}

const BUF: usize = 16 * 1024;

fn cstr(p: *const u8) -> string {
    if p.is_null() {
        return string::from_static("");
    }
    let mut n = 0;
    unsafe {
        while *p.add(n) != 0 {
            n += 1;
        }
        string::from_bytes(core::slice::from_raw_parts(p, n))
    }
}

fn c_name(s: &string) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

// go: sdk 1.25.5 os/user/cgo_lookup_unix.go buildUser
fn build_user(pwd: &Passwd) -> User {
    // Go: u.Name, _, _ = strings.Cut(u.Name, ",") — pw_gecos is a
    // comma-separated list whose first item is the full name.
    let (name, _, _) = strings::Cut(cstr(pwd.pw_gecos), string::from_static(","));
    User {
        Uid: strconv::Itoa(crate::int(pwd.pw_uid as i64)),
        Gid: strconv::Itoa(crate::int(pwd.pw_gid as i64)),
        Username: cstr(pwd.pw_name),
        Name: name,
        HomeDir: cstr(pwd.pw_dir),
    }
}

// go: sdk 1.25.5 os/user/cgo_lookup_unix.go buildGroup
fn build_group(grp: &CGroup) -> Group {
    Group {
        Gid: strconv::Itoa(crate::int(grp.gr_gid as i64)),
        Name: cstr(grp.gr_name),
    }
}

/// Go's `fmt.Errorf("user: lookup … %v", err)` for a libc failure other
/// than "not found".
fn lookup_err(what: &str, key: string, e: i32) -> error {
    errors::New(
        string::from(what) + key + string::from_static(": ") + crate::syscall::Errno(e).Error(),
    )
}

// go: sdk 1.25.5 os/user/cgo_lookup_unix.go lookupUser
pub(super) fn lookup_user(username: string) -> (User, error) {
    let name = c_name(&username);
    let mut pwd: Passwd = unsafe { core::mem::zeroed() };
    let mut res: *mut Passwd = core::ptr::null_mut();
    let mut buf = alloc::vec![0u8; BUF];
    let e = unsafe { getpwnam_r(name.as_ptr(), &mut pwd, buf.as_mut_ptr(), BUF, &mut res) };
    // Go: err == syscall.ENOENT || (err == nil && !found) → unknown.
    if e == crate::syscall::ENOENT.0 || (e == 0 && res.is_null()) {
        return (User::default(), UnknownUserError::new(username));
    }
    if e != 0 {
        return (User::default(), lookup_err("user: lookup username ", username, e));
    }
    (build_user(&pwd), errors::nil)
}

// go: sdk 1.25.5 os/user/cgo_lookup_unix.go lookupUserId + lookupUnixUid
pub(super) fn lookup_user_id(uid: string) -> (User, error) {
    let (i, e) = strconv::Atoi(uid.clone());
    if !e.IsNil() {
        return (User::default(), e);
    }
    let mut pwd: Passwd = unsafe { core::mem::zeroed() };
    let mut res: *mut Passwd = core::ptr::null_mut();
    let mut buf = alloc::vec![0u8; BUF];
    let r = unsafe { getpwuid_r(i as u32, &mut pwd, buf.as_mut_ptr(), BUF, &mut res) };
    if r == crate::syscall::ENOENT.0 || (r == 0 && res.is_null()) {
        return (User::default(), UnknownUserIdError::new(crate::int(i)));
    }
    if r != 0 {
        return (User::default(), lookup_err("user: lookup userid ", uid, r));
    }
    (build_user(&pwd), errors::nil)
}

// go: sdk 1.25.5 os/user/cgo_lookup_unix.go lookupGroup
pub(super) fn lookup_group(name: string) -> (Group, error) {
    let cname = c_name(&name);
    let mut grp: CGroup = unsafe { core::mem::zeroed() };
    let mut res: *mut CGroup = core::ptr::null_mut();
    let mut buf = alloc::vec![0u8; BUF];
    let e = unsafe { getgrnam_r(cname.as_ptr(), &mut grp, buf.as_mut_ptr(), BUF, &mut res) };
    if e == crate::syscall::ENOENT.0 || (e == 0 && res.is_null()) {
        return (Group::default(), UnknownGroupError::new(name));
    }
    if e != 0 {
        return (Group::default(), lookup_err("user: lookup groupname ", name, e));
    }
    (build_group(&grp), errors::nil)
}

// go: sdk 1.25.5 os/user/cgo_lookup_unix.go lookupGroupId + lookupUnixGid
pub(super) fn lookup_group_id(id: string) -> (Group, error) {
    let (i, e) = strconv::Atoi(id.clone());
    if !e.IsNil() {
        return (Group::default(), e);
    }
    let mut grp: CGroup = unsafe { core::mem::zeroed() };
    let mut res: *mut CGroup = core::ptr::null_mut();
    let mut buf = alloc::vec![0u8; BUF];
    let r = unsafe { getgrgid_r(i as u32, &mut grp, buf.as_mut_ptr(), BUF, &mut res) };
    if r == crate::syscall::ENOENT.0 || (r == 0 && res.is_null()) {
        return (Group::default(), UnknownGroupIdError::new(id));
    }
    if r != 0 {
        return (Group::default(), lookup_err("user: lookup groupid ", id, r));
    }
    (build_group(&grp), errors::nil)
}
