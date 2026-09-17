// SPDX-License-Identifier: GPL-3.0-or-later

use core::{
    error::Error,
    fmt::{self, Display, Formatter},
};

#[cfg(unix)]
use rustix::io::Errno;

#[derive(Clone, Copy, Debug)]
pub struct SandboxError {
    #[cfg(unix)]
    pub errno: Errno,
    pub stage: Stage,
    pub action: Action,
    pub context: Option<&'static str>,
}

impl Error for SandboxError {
    #[cfg(unix)]
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.errno)
    }
}

impl Display for SandboxError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Building sandbox:\n
            Stage: {}\n
            {}: {}\n
            Context: {}",
            self.stage,
            self.action,
            self.errno,
            self.context.unwrap_or_default()
        )
    }
}

impl SandboxError {
    #[cfg(unix)]
    pub const fn buf_full(stage: Stage, context: &'static str) -> Self {
        Self {
            errno: Errno::NOSPC,
            stage,
            action: Action::WriteBuf,
            context: Some(context),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Stage {
    BindMountPaths,
    CloneNamespace,
    MakeNewRoot,
    MountNamespace,
    MountNewRoot,
    PivotRoot,
    WriteIdMap,
}

impl Display for Stage {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::BindMountPaths => write!(f, "bind mounting paths in NEWNS"),
            Self::CloneNamespace => write!(f, "clone3 into new namespaces"),
            Self::MakeNewRoot => write!(f, "making a private root for pivot_root"),
            Self::MountNamespace => write!(f, "building mount namespace (NEWNS)"),
            Self::MountNewRoot => write!(f, "mounting/attaching new root"),
            Self::PivotRoot => write!(f, "pivoting to new root"),
            Self::WriteIdMap => write!(f, "writing namespace UID/GID map"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Action {
    ChangeDir,
    Clone,
    EventfdNew,
    FsConfig,
    FsCreate,
    FsOpen,
    Mkdir,
    Mount,
    MoveMount,
    OpenDir,
    OpenFile,
    OpenTree,
    PivotRoot,
    ReadFile,
    SaneSecurity,
    Stat,
    Unmount,
    Unshare,
    WriteBuf,
    WriteFile,
}

impl Display for Action {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChangeDir => write!(f, "changing current working directory"),
            Self::Clone => write!(f, "clone3 syscall"),
            Self::EventfdNew => write!(f, "opening an eventfd"),
            Self::FsConfig => write!(f, "configuring FS context (fs_config)"),
            Self::FsCreate => write!(f, "creating FS from config context (fs_create)"),
            Self::FsOpen => write!(f, "opening new FS config context (fs_open)"),
            Self::Mkdir => write!(f, "mkdir"),
            Self::Mount => write!(f, "mount syscall"),
            Self::MoveMount => write!(f, "move_mount syscall"),
            Self::OpenDir => write!(f, "opening a directory descriptor"),
            Self::OpenFile => write!(f, "opening a file descriptor"),
            Self::OpenTree => write!(f, "open_tree (bind mounting path)"),
            Self::PivotRoot => write!(f, "pivot_root to new root"),
            Self::ReadFile => write!(f, "reading from a file"),
            Self::SaneSecurity => write!(f, "sanity check"),
            Self::Stat => write!(f, "stat family of syscalls"),
            Self::Unmount => write!(f, "umount syscall"),
            Self::Unshare => write!(f, "unshare syscall"),
            Self::WriteBuf => write!(f, "writing to an in-memory buffer"),
            Self::WriteFile => write!(f, "writing to a file"),
        }
    }
}

/// Sandbox success state.
///
/// Entering the sandbox differs per operating system because Emimg makes use of primitives like
/// `clone3`. Thus, the caller needs to drive sandbox creation based on state per operating
/// system. For some targets, a new process is created so the parent may be discarded.
/// Arbitrary file access is usually restricted, so a separate state exists for that as well.
#[derive(Clone, Copy)]
pub enum SandboxSuccess {
    Child,
    Parent,
}
