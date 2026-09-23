// os/user — module root.
//
// Split the way Go splits it: `user.rs` for the value types and their
// errors, `lookup.rs` for the public lookups, `lookup_unix.rs` for the
// /etc/passwd and /etc/group readers. This file re-exports, so callers
// keep writing `user::Current()` and `user::Lookup(name)`.

mod lookup;
#[cfg(not(target_os = "macos"))]
mod lookup_unix;
// Darwin: the libc lookups Go's default (cgo) darwin build uses —
// accounts live in Directory Services, not /etc/passwd.
#[cfg(target_os = "macos")]
#[path = "cgo_lookup_darwin.rs"]
mod lookup_unix;
mod user;

pub use lookup::{Current, Lookup, LookupGroup, LookupGroupId, LookupId};
pub use user::{
    Group, UnknownGroupError, UnknownGroupIdError, UnknownUserError, UnknownUserIdError, User,
};
