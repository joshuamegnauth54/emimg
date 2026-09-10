// SPDX-License-Identifier: GPL-3.0-or-later

pub mod mount_namespace;
pub mod user_namespace;

use rustix::fs::{OFlags, ResolveFlags};

pub const DIR_FLAGS: OFlags = OFlags::from_bits(
    OFlags::CLOEXEC.bits()
        | OFlags::DIRECTORY.bits()
        | OFlags::NOFOLLOW.bits()
        | OFlags::PATH.bits(),
)
.expect("valid OFlags bits");

pub const RESOLVE_BENEATH_FLAGS: ResolveFlags = ResolveFlags::from_bits(
    ResolveFlags::BENEATH.bits()
        | ResolveFlags::NO_MAGICLINKS.bits()
        | ResolveFlags::NO_SYMLINKS.bits()
        | ResolveFlags::NO_XDEV.bits(),
)
.expect("valid ResolveFlags bits");
