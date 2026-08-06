// SPDX-License-Identifier: GPL-3.0-or-later

#[cfg(feature = "rust-libc")]
use libc_rust as libc;

use core::{fmt::Write, hint::cold_path, mem::size_of};

use libc::{SYS_clone3, clone_args, syscall};
use rustix::{
    event::{EventfdFlags, eventfd},
    fd::{AsFd, OwnedFd},
    fs::{CWD, Mode, OFlags, ResolveFlags, openat2},
    io::{self, Errno, write},
    path,
    process::{self, Pid, Signal},
    thread::UnshareFlags,
};

use crate::{
    error::{Action, SandboxError, Stage},
    utils::BufferFmtWriter,
};

const DIR_FLAGS: OFlags = OFlags::from_bits(
    OFlags::CLOEXEC.bits()
        | OFlags::DIRECTORY.bits()
        | OFlags::NOATIME.bits()
        | OFlags::NOCTTY.bits()
        | OFlags::NOFOLLOW.bits()
        | OFlags::PATH.bits(),
)
.expect("valid OFlags bits");

const FILE_FLAGS: OFlags = OFlags::from_bits(
    OFlags::CLOEXEC.bits()
        | OFlags::NOATIME.bits()
        | OFlags::NOCTTY.bits()
        | OFlags::NOFOLLOW.bits()
        | OFlags::WRONLY.bits(),
)
.expect("valid OFlags bits");

const FILE_RESOLVE_FLAGS: ResolveFlags = ResolveFlags::from_bits(
    ResolveFlags::BENEATH.bits()
        | ResolveFlags::IN_ROOT.bits()
        | ResolveFlags::NO_MAGICLINKS.bits()
        | ResolveFlags::NO_SYMLINKS.bits()
        | ResolveFlags::NO_XDEV.bits(),
)
.expect("valid ResolveFlags bits");

#[derive(Clone, Copy)]
pub enum SandboxClone {
    Parent,
    Child,
}

/// Sandbox the current process by entering a bespoke user namespace.
///
/// # Safety
/// * A new process is started with clone3 without sharing resources (no CLONE_VM)
/// * The caller must ensure a limited execution environment by avoiding spawning threads.
/// Threads can cause an inconsistent environment in the child (i.e. if locks are held by a thread
/// the child can deadlock).
pub unsafe fn sandbox_process() -> Result<SandboxClone, SandboxError> {
    let events = eventfd(0, EventfdFlags::CLOEXEC).map_err(|errno| SandboxError {
        errno,
        stage: Stage::CloneNamespace,
        action: Action::EventfdNew,
        context: Some("opening an eventfd to synch between parent and child"),
    })?;
    let clone3_args = clone_args {
        // The rest of the permissions will be unshare'd and seccomp'd.
        flags: (UnshareFlags::NEWPID
            | UnshareFlags::NEWTIME
            | UnshareFlags::NEWNET
            | UnshareFlags::NEWNS
            | UnshareFlags::NEWUSER
            | UnshareFlags::NEWUTS)
            .bits() as u64,
        pidfd: 0, // TODO: USE PIDFD
        child_tid: 0,
        parent_tid: 0,
        exit_signal: libc::SIGCHLD as u64,
        stack: 0,
        stack_size: 0,
        set_tid: 0,
        set_tid_size: 0,
        tls: 0,
        cgroup: 0, // TODO: USE CGROUP?
    };

    // SAFETY:
    // * We're currently single threaded and won't create new threads until sandboxing succeeds.
    // * We don't use any shared resources besides the eventfd descriptor.
    // * clone_args is ABI correct because it comes from libc.
    let pid =
        unsafe { syscall(SYS_clone3, &raw const clone3_args, size_of::<clone_args>()) as i64 };

    if pid > 0 {
        // PARENT

        // This should be impossible but may as well check.
        let Ok(pid) = pid.try_into() else {
            cold_path();
            panic!("SANDBOX: Child PID ({pid}) too large to fit into RawPid");
        };
        let pid = Pid::from_raw(pid)
            .unwrap_or_else(|| panic!("SANDBOX: Child PID ({pid}) should be > 0"));
        if let Err(e) = parent_write_id_map(pid, events) {
            process::kill_process(pid, Signal::KILL).unwrap();
            panic!("SANDBOX: Failed to write UID/GID map ({e})");
        };

        // Kill parent because we don't need it anymore.
        return Ok(SandboxClone::Parent);
    } else if pid < 0 {
        cold_path();
        // SAFETY: clone3 failed so we're still in our main process.
        Err(SandboxError {
            errno: Errno::from_raw_os_error(unsafe { *libc::__errno_location() }),
            stage: Stage::CloneNamespace,
            action: Action::Clone,
            context: Some("in main process; no child should exist"),
        })?;
    }

    #[cfg(debug_assertions)]
    if pid != 0 {
        // Somehow, we're still the parent process.
        process::kill_process(
            Pid::from_raw(pid.try_into().unwrap()).unwrap(),
            Signal::KILL,
        )
        .unwrap();
        panic!("SANDBOX: Parent unexpectedly alive after writing UID/GID map");
    }

    child_unshare_all(events)
}

/// Write the user namespace UID/GID map to ensure correct permissions.
///
/// ## Warning
///
/// **DO NOT** panic. Return an error so that the parent process can clean up.
fn parent_write_id_map(child: Pid, events: OwnedFd) -> Result<(), SandboxError> {
    // Open root and /proc with openat2.
    // NO_XDEV is irrelevant here but I like having it anyway.
    // Since I am opening an absolute path, this should succeed regardless of CWD.
    let root = openat2(
        CWD,
        "/",
        DIR_FLAGS,
        Mode::empty(),
        ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
    )
    .map_err(|errno| SandboxError {
        errno,
        stage: Stage::WriteIdMap,
        action: Action::OpenDir,
        context: Some("opening directory descriptor for /"),
    })?;
    // root -> proc mount transition. NO_XDEV is not used here due to the mount transition.
    let proc_dir = openat2(
        root,
        "proc",
        DIR_FLAGS,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|errno| SandboxError {
        errno,
        stage: Stage::WriteIdMap,
        action: Action::OpenDir,
        context: Some("opening directory descriptor for /proc"),
    })?;

    // Open /proc/{child} with openat2
    let mut scratch_buf = [0u8; libc::PATH_MAX as usize];
    let mut scratch = BufferFmtWriter::new(&mut scratch_buf);
    write!(scratch, "{child}").map_err(|_| {
        SandboxError::buf_full(Stage::WriteIdMap, "writing child PID into scratch buf")
    })?;
    let proc_dir = openat2(
        proc_dir,
        scratch.as_str(),
        DIR_FLAGS,
        Mode::empty(),
        FILE_RESOLVE_FLAGS,
    )
    .map_err(|errno| SandboxError {
        errno,
        stage: Stage::WriteIdMap,
        action: Action::OpenDir,
        context: Some("opening /proc/{pid}"),
    })?;

    // Disable setgroups because sandboxed processes aren't allowed to set supplementary groups.
    write_proc(
        &proc_dir,
        "setgroups",
        "deny".as_bytes(),
        "opening /proc/{pid}/setgroups",
        "writing 'deny' to /proc/{pid}/setgroups",
        "short write while writing 'deny' to /proc/{pid}/setgroups",
    )?;

    // Map namespace's internal root to our current UID/GID.
    let uid = process::getuid();
    let gid = process::getgid();
    if uid.is_root() || gid.is_root() {
        cold_path();
        return Err(SandboxError {
            errno: Errno::PERM,
            stage: Stage::WriteIdMap,
            action: Action::SaneSecurity,
            context: Some("DUDE WHY ARE YOU ROOT"),
        });
    }

    // UID
    scratch.clear();
    writeln!(scratch, "0 {uid} 1").map_err(|_| {
        SandboxError::buf_full(Stage::WriteIdMap, "writing UID map to in memory buffer")
    })?;
    write_proc(
        &proc_dir,
        "uid_map",
        scratch.as_bytes(),
        "opening /proc/{pid}/uid_map",
        "writing /proc/{pid}/uid_map to map namespace root to current UID",
        "short write while writing UID map to /proc/{pid}/uid_map",
    )?;

    // GID
    scratch.clear();
    writeln!(scratch, "0 {gid} 1").map_err(|_| {
        SandboxError::buf_full(Stage::WriteIdMap, "writing GID map to in memory buffer")
    })?;
    write_proc(
        &proc_dir,
        "gid_map",
        scratch.as_bytes(),
        "opening /proc/{pid}/gid_map",
        "writing /proc/{pid}/gid_map to map namespace root to current GID",
        "short write while writing GID map to /proc/{pid}/gid_map",
    )?;

    // Signal the child that parent-side setup is complete.
    if io::write(&events, &1u64.to_ne_bytes()).map_err(|errno| SandboxError {
        errno,
        stage: Stage::WriteIdMap,
        action: Action::WriteFile,
        context: Some("bumping eventfd counter to signal namespace process"),
    })? != size_of::<u64>()
    {
        cold_path();
        Err(SandboxError {
            errno: Errno::IO,
            stage: Stage::WriteIdMap,
            action: Action::WriteFile,
            context: Some("bumping eventfd counter; the full buffer wasn't written"),
        })
    } else {
        Ok(())
    }
}

fn write_proc(
    proc_dir: impl AsFd,
    path: impl path::Arg,
    buf: &[u8],
    open_err: &'static str,
    write_err: &'static str,
    short_write: &'static str,
) -> Result<(), SandboxError> {
    let fd = openat2(
        proc_dir,
        path,
        FILE_FLAGS,
        Mode::empty(),
        FILE_RESOLVE_FLAGS,
    )
    .map_err(|errno| SandboxError {
        errno,
        stage: Stage::WriteIdMap,
        action: Action::WriteFile,
        context: Some(open_err),
    })?;

    // Short writes are invalid for /proc. Retrying a short write rewrites the entire proc file.
    loop {
        match write(&fd, buf) {
            Ok(n) if n == buf.len() => break Ok(()),
            Ok(_) => {
                cold_path();
                break Err(SandboxError {
                    errno: Errno::IO,
                    stage: Stage::WriteIdMap,
                    action: Action::WriteFile,
                    context: Some(short_write),
                });
            }
            Err(errno) if errno == Errno::INTR => {
                cold_path();
                continue;
            }
            Err(errno) => {
                cold_path();
                break Err(SandboxError {
                    errno,
                    stage: Stage::WriteIdMap,
                    action: Action::WriteFile,
                    context: Some(write_err),
                });
            }
        }
    }
}

// Mount required directories and drop permissions.
fn child_unshare_all(events: OwnedFd) -> Result<SandboxClone, SandboxError> {
    // Wait for parent to signal that it's finished.
    let mut event_buf = 0u64.to_ne_bytes();
    let nread = io::read(&events, &mut event_buf).map_err(|errno| SandboxError {
        errno,
        stage: Stage::WriteIdMap,
        action: Action::ReadFile,
        context: Some("reading from eventfd counter in the child process"),
    })?;
    if nread != size_of::<u64>() || u64::from_ne_bytes(event_buf) != 1 {
        cold_path();
        return Err(SandboxError {
            errno: Errno::IO,
            stage: Stage::WriteIdMap,
            action: Action::ReadFile,
            context: Some("reading from eventfd counter; buffer is truncated"),
        });
    }

    // SAFETY: No resources are shared from parent process to child.
    // This invariant is upheld by main().
    // unsafe {
    //     unshare_unsafe(
    //         UnshareFlags::NEWNS
    //             | UnshareFlags::NEWNET
    //             | UnshareFlags::NEWIPC
    //             | UnshareFlags::NEWTIME,
    //     )?;
    // }
    Ok(SandboxClone::Child)
}

// #[cold]
// fn from_io_error(e: std::io::Error) -> Errno {
//     Errno::from_io_error(&e).unwrap_or(Errno::IO)
// }
