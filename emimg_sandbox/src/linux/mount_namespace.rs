// SPDX-License-Identifier: GPL-3.0-or-later

#[cfg(feature = "rust-libc")]
use libc_rust as libc;

use core::{ffi::CStr, fmt::Write};

use rustix::{
    fd::{AsFd, OwnedFd},
    fs::{
        AtFlags, CWD, FileType, Mode, OFlags, ResolveFlags, StatxFlags, mkdir, mkdirat, openat2,
        statx,
    },
    io::Errno,
    mount::{
        FsMountFlags, FsOpenFlags, MountAttrFlags, MountFlags, MountPropagationFlags,
        MoveMountFlags, OpenTreeFlags, UnmountFlags, fsconfig_create_exclusive,
        fsconfig_set_string, fsmount, fsopen, mount, mount_change, move_mount, open_tree, unmount,
    },
    path::Arg,
    process::{chdir, fchdir, pivot_root},
    thread::{UnshareFlags, unshare_unsafe},
};

use crate::{
    Action, SandboxError, Stage,
    linux::{DIR_FLAGS, RESOLVE_BENEATH_FLAGS},
    utils::BufferFmtWriter,
};

pub const NEW_ROOT: &CStr = c"/emilinya";
pub const ROOT_MNT: &CStr = c"/emilinya/decoded";
pub const BIND_MNT: &CStr = c"decoded";

/// Create a bespoke mount namespace of untrusted paths.
pub fn mount_namespace<I>(paths: I) -> Result<(), SandboxError>
where
    I: IntoIterator,
    I::Item: Arg,
{
    // Place the decoder into its own mount namespace.
    // The supervisor is already in its own namespace, but all three processes should ideally be
    // separate and only communicate via IPC.
    unsafe { unshare_unsafe(UnshareFlags::NEWNS) }.map_err(|errno| SandboxError {
        errno,
        stage: Stage::MountNamespace,
        action: Action::Unshare,
        context: Some("entering new mount namespace in decoder"),
    })?;

    // MS_PRIVATE
    private_recursive_mount(Stage::MountNamespace, "MS_PRIVATE in decoder process")?;

    // Temporary root for decoder
    let StagingRoot { new_root, bind_mnt } = make_staging_root()?;

    // Bind mount user provided paths into our new tmpfs.
    bind_mount_paths(bind_mnt, paths)?;

    // Attach detached new root
    mount_staging_root(&new_root)?;

    // pivot_root
    pivot_new_root(new_root)?;

    // MS_UNBINDABLE
    // UNBINDABLE can't be set earlier because I'm bind mounting files from this namespace into this
    // namespace. In other words, it's both the source and destination.
    unbindable_recursive_mount(Stage::MountNamespace, "MS_UNBINDABLE in decoder process")?;

    // Drop capabilities
    // seal_mount()?;
    todo!()
}

/// Recursively impede mount event propagation from this process's peer group.
///
/// See:
/// * https://lwn.net/Articles/689856/
/// * https://lwn.net/Articles/690679/
#[inline]
pub fn private_recursive_mount(stage: Stage, context: &'static str) -> Result<(), SandboxError> {
    // MS_PRIVATE
    // Prevent mount events outside of this namespace from propagating to this namespace.
    mount_change(
        c"/",
        MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
    )
    .map_err(|errno| SandboxError {
        errno,
        stage,
        action: Action::Mount,
        context: Some(context),
    })
}

/// Recursively impede mount event propagation and prevent this mount from acting as a source.
///
/// See:
/// * [`private_recursive_mount`]
/// * https://lwn.net/Articles/689856/
/// * https://lwn.net/Articles/690679/
#[inline]
pub fn unbindable_recursive_mount(stage: Stage, context: &'static str) -> Result<(), SandboxError> {
    // MS_UNBINDABLE
    // Prevent the new mount from acting as a source (e.g. mount /this /attacker).
    mount_change(
        c"/",
        MountPropagationFlags::UNBINDABLE | MountPropagationFlags::REC,
    )
    .map_err(|errno| SandboxError {
        errno,
        stage,
        action: Action::Mount,
        context: Some(context),
    })
}

struct StagingRoot {
    new_root: OwnedFd,
    bind_mnt: OwnedFd,
}

/// Pivot root to a private, controlled, and process-only tree.
///
/// The process must have CAP_SYS_ADMIN and a recursive private mount tree (MS_REC | MS_PRIVATE).
fn make_staging_root() -> Result<StagingRoot, SandboxError> {
    // Open a blank TMPFS configuration context.
    // https://man7.org/linux/man-pages/man2/fsopen.2.html
    let fs_fd = fsopen(c"tmpfs", FsOpenFlags::FSOPEN_CLOEXEC).map_err(|errno| SandboxError {
        errno,
        stage: Stage::MakeNewRoot,
        action: Action::FsOpen,
        context: Some("opening blank TMPFS config context"),
    })?;

    // Set options on empty FS config context.
    // https://man7.org/linux/man-pages/man2/fsconfig.2.html
    fsconfig_opt(
        &fs_fd,
        c"size",
        c"16M",
        "setting max size on new TMPFS context",
    )?;
    fsconfig_opt(&fs_fd, c"mode", c"700", "setting mode on new TMPFS context")?;

    // After configuration, the file system needs to be created.
    // FSCONFIG_CMD_CREATE_EXCL doesn't reuse extant, compatible instances. While it is unlikely
    // that an instance would be reused in my case, it's cleaner to explicitly ensure it isn't.
    fsconfig_create_exclusive(&fs_fd).map_err(|errno| SandboxError {
        errno,
        stage: Stage::MakeNewRoot,
        action: Action::FsCreate,
        context: Some("exclusively creating new TMPFS superblock"),
    })?;

    // Create a detached mount for TMPFS.
    // The docs say that the config context can be closed at this point, so I'm explicitly passing
    // ownership to fsmount.
    let new_root = fsmount(
        fs_fd,
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::MOUNT_ATTR_IDMAP
            | MountAttrFlags::MOUNT_ATTR_NOATIME
            | MountAttrFlags::MOUNT_ATTR_NODEV
            | MountAttrFlags::MOUNT_ATTR_NOEXEC
            | MountAttrFlags::MOUNT_ATTR_NOSUID
            | MountAttrFlags::MOUNT_ATTR_NOSYMFOLLOW,
    )
    .map_err(|errno| SandboxError {
        errno,
        stage: Stage::MakeNewRoot,
        action: Action::Mount,
        context: Some("spawning detached TMPFS new root"),
    })?;

    // Directory to bind mount user files (zero trust)
    mkdirat(&new_root, BIND_MNT, Mode::RWXU).map_err(|errno| SandboxError {
        errno,
        stage: Stage::MakeNewRoot,
        action: Action::Mkdir,
        context: Some("making directory to bind mount user files"),
    })?;

    openat2(
        &new_root,
        BIND_MNT,
        DIR_FLAGS,
        Mode::empty(),
        RESOLVE_BENEATH_FLAGS,
    )
    .map(|bind_mnt| StagingRoot { new_root, bind_mnt })
    .map_err(|errno| SandboxError {
        errno,
        stage: Stage::MakeNewRoot,
        action: Action::OpenDir,
        context: Some("opening bind mount directory under new root"),
    })

    // let new_root = openat2(
    //     CWD,
    //     NEW_ROOT,
    //     DIR_FLAGS,
    //     Mode::empty(),
    //     ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    // )
    // .map_err(|errno| SandboxError {
    //     errno,
    //     stage: Stage::MakeNewRoot,
    //     action: Action::OpenDir,
    //     context: Some("opening new root for bind mounts"),
    // })?;
}

/// Attach detached mount context.
fn mount_staging_root(mnt_fd: impl AsFd) -> Result<(), SandboxError> {
    // Create a mount point at NEW_ROOT to use for pivot_root
    mkdir(NEW_ROOT, Mode::RWXU).map_err(|errno| SandboxError {
        errno,
        stage: Stage::MountNewRoot,
        action: Action::Mkdir,
        context: Some("making new root under /"),
    })?;

    // Attach mount under NEW_ROOT
    move_mount(
        mnt_fd,
        c"",
        CWD,
        NEW_ROOT,
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )
    .map_err(|errno| SandboxError {
        errno,
        stage: Stage::MountNewRoot,
        action: Action::MoveMount,
        context: Some("moving detached mount to new root"),
    })
}

/// [`fsconfig_set_string`] helper.
#[inline]
fn fsconfig_opt(
    fs_fd: impl AsFd,
    key: &CStr,
    value: &CStr,
    context: &'static str,
) -> Result<(), SandboxError> {
    fsconfig_set_string(fs_fd, key, value).map_err(|errno| SandboxError {
        errno,
        stage: Stage::MakeNewRoot,
        action: Action::FsConfig,
        context: Some(context),
    })
}

/// Bind mount paths into BIND_MNT with very minimal scrubbing.
fn bind_mount_paths<I>(target: impl AsFd, paths: I) -> Result<(), SandboxError>
where
    I: IntoIterator,
    I::Item: Arg,
{
    let mut scratch_buf = [0u8; libc::PATH_MAX as usize];
    let mut scratch = BufferFmtWriter::new(&mut scratch_buf);

    // TODO: io_uring?
    for (i, path) in paths.into_iter().enumerate() {
        let src_fd = openat2(
            CWD,
            path,
            OFlags::CLOEXEC | OFlags::NOATIME | OFlags::NOCTTY | OFlags::PATH,
            Mode::empty(),
            ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|errno| SandboxError {
            errno,
            stage: Stage::BindMountPaths,
            action: Action::OpenFile,
            context: Some("opening untrusted user path for bind mounts"),
        })?;

        let stat = statx(&src_fd, c"", AtFlags::EMPTY_PATH, StatxFlags::TYPE).map_err(|errno| {
            SandboxError {
                errno,
                stage: Stage::BindMountPaths,
                action: Action::Stat,
                context: Some("stat descriptor to reject invalid node types"),
            }
        })?;
        let ft = FileType::from_raw_mode(stat.stx_mode as u32);

        if !ft.is_file() || !ft.is_dir() {
            // XXX: Should this be logged?
            continue;
        }

        // An empty path + AT_EMPTY_PATH allows using either a directory descriptor OR file
        // descriptor. This open_tree call creates a detached bind mount of src_fd.
        let tree_fd = open_tree(
            src_fd,
            c"",
            OpenTreeFlags::OPEN_TREE_CLONE
                | OpenTreeFlags::OPEN_TREE_CLOEXEC
                | OpenTreeFlags::AT_EMPTY_PATH,
        )
        .map_err(|errno| SandboxError {
            errno,
            stage: Stage::BindMountPaths,
            action: Action::OpenTree,
            context: Some("creating a detached bind-mount of a user provided path"),
        })?;

        // Monotonically increasing names.
        // I can avoid this if I take in &[Path], but I kind of like that this is no_std.
        scratch.clear();
        write!(scratch, "{i}").map_err(|_| {
            SandboxError::buf_full(
                Stage::BindMountPaths,
                "writing temp file name into scratch buf",
            )
        })?;
        let target_name = scratch.as_c_str().ok_or(SandboxError::buf_full(
            Stage::BindMountPaths,
            "C string temp file file",
        ))?;

        // Attach detached bind mount by moving it under my new root
        move_mount(
            tree_fd,
            c"",
            &target,
            target_name,
            MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
        )
        .map_err(|errno| SandboxError {
            errno,
            stage: Stage::BindMountPaths,
            action: Action::MoveMount,
            context: Some("moving bind mounted user path under new root"),
        })?;
    }

    Ok(())
}

fn pivot_new_root(new_root: impl AsFd) -> Result<(), SandboxError> {
    fchdir(new_root).map_err(|errno| SandboxError {
        errno,
        stage: Stage::PivotRoot,
        action: Action::ChangeDir,
        context: Some("changing process CWD to the new root"),
    })?;

    // This pivots CWD, which is now new_root, to root. old_root is stacked on top of new_root.
    pivot_root(c".", c".").map_err(|errno| SandboxError {
        errno,
        stage: Stage::PivotRoot,
        action: Action::PivotRoot,
        context: Some("pivoting CWD (new root) and stacking old root onto new root"),
    })?;

    // Detach the stacked old_root which reveals new_root
    unmount(c".", UnmountFlags::DETACH | UnmountFlags::NOFOLLOW).map_err(|errno| SandboxError {
        errno,
        stage: Stage::PivotRoot,
        action: Action::Unmount,
        context: Some("detaching old root mount that's stacked on new root"),
    })?;

    chdir(c"/").map_err(|errno| SandboxError {
        errno,
        stage: Stage::PivotRoot,
        action: Action::ChangeDir,
        context: Some("cd / in mount namespace to new root after detaching old root"),
    })
}
