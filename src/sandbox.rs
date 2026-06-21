// SPDX-License-Identifier: GPL-3.0-or-later

#[cfg(target_os = "linux")]
mod linux;
pub use linux::sandbox_process;
