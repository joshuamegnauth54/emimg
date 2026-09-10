// SPDX-License-Identifier: GPL-3.0-or-later

#![cfg_attr(target_os = "linux", no_std)]

#[cfg(target_os = "linux")]
mod linux;
pub use linux::{
    mount_namespace::{mount_namespace, private_recursive_mount, unbindable_recursive_mount},
    user_namespace::{SandboxClone, enter_user_namespace},
};

mod error;
pub use error::{Action, SandboxError, SandboxSuccess, Stage};

mod utils;
