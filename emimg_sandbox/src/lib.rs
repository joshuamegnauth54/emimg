// SPDX-License-Identifier: GPL-3.0-or-later

#![cfg_attr(target_os = "linux", no_std)]

#[cfg(target_os = "linux")]
mod linux;
pub use linux::sandbox_process;

mod error;
pub use error::{Action, SandboxError, SandboxSuccess, Stage};

mod utils;
