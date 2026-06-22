// SPDX-License-Identifier: GPL-3.0-or-later

#[cfg(feature = "rust-libc")]
use libc_rust as libc;

use core::{fmt::Write, hint::cold_path, mem::size_of};

use cap_std::{AmbientAuthority, fs};
use libc::{SYS_clone3, clone_args, syscall};
use rustix::{
    event::{EventfdFlags, eventfd},
    fd::OwnedFd,
    io::{self, Errno, Result},
    process::{self, Pid, Signal},
    thread::UnshareFlags,
};

use crate::utils::BufferFmtWriter;

pub unsafe fn sandbox_process(ambient_authority: AmbientAuthority) -> Result<()> {
    let efd1 = eventfd(0, EventfdFlags::CLOEXEC)?;
    let efd2 = eventfd(0, EventfdFlags::CLOEXEC)?;
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
        if let Err(e) = parent_write_id_map(pid, efd1, efd2, ambient_authority) {
            process::kill_process(pid, Signal::KILL).unwrap();
            panic!("SANDBOX: Failed to write UID/GID map ({e})");
        };

        // Kill parent because we don't it anymore.
        unsafe { libc::_exit(libc::EXIT_SUCCESS) };
    } else if pid < 0 {
        cold_path();
        // SAFETY: clone3 failed so we're still in our main process.
        Err(Errno::from_raw_os_error(unsafe {
            *libc::__errno_location()
        }))?;
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

    child_unshare_all(efd2, efd1)
}

/// Write the user namespace UID/GID map.
///
/// ## Warning
///
/// **DO NOT** panic. Return an error so that the parent process can clean up.
fn parent_write_id_map(
    child: Pid,
    from: OwnedFd,
    to: OwnedFd,
    ambient_authority: AmbientAuthority,
) -> Result<()> {
    let mut event_buf = 0u64.to_ne_bytes();

    // Wait for the child to signal it's ready for the map.
    let nread = io::read(&from, &mut event_buf)?;
    if nread != size_of::<u64>() || u64::from_ne_bytes(event_buf) != 1 {
        return Err(Errno::IO);
    }

    // Open /proc/{child} with openat2
    let proc_dir = fs::Dir::open_ambient_dir("/proc", ambient_authority).map_err(from_io_error)?;
    let mut scratch_buf = [0u8; libc::PATH_MAX as usize];
    let mut scratch = BufferFmtWriter::new(&mut scratch_buf);
    write!(scratch, "{child}").map_err(|_| Errno::NOSPC)?;
    let proc_dir = proc_dir.open_dir(scratch.as_str()).map_err(from_io_error)?;

    // Disable setgroups because sandboxed processes aren't allowed to set supplementary groups.
    proc_dir.write("setgroups", "deny").map_err(from_io_error)?;

    // Map namespace's internal root to our current UID/GID.
    let uid = process::getuid();
    let gid = process::getgid();
    if uid.is_root() || gid.is_root() {
        cold_path();
        return Err(Errno::PERM);
    }

    // UID
    scratch.clear();
    writeln!(scratch, "0 {uid} 1").map_err(|_| Errno::NOSPC)?;
    proc_dir
        .write("uid_map", scratch.as_str())
        .map_err(from_io_error)?;

    // GID
    scratch.clear();
    writeln!(scratch, "0 {gid} 1").map_err(|_| Errno::NOSPC)?;
    proc_dir
        .write("gid_map", scratch.as_str())
        .map_err(from_io_error)?;

    // Signal the child that parent-side setup is complete.
    if io::write(&to, &1u64.to_ne_bytes())? != size_of::<u64>() {
        cold_path();
        Err(Errno::IO)
    } else {
        Ok(())
    }
}

// Mount required directories and drop permissions.
fn child_unshare_all(from: OwnedFd, to: OwnedFd) -> Result<()> {
    // Signal the parent to write the map.
    if io::write(&to, &1u64.to_ne_bytes())? != size_of::<u64>() {
        return Err(Errno::IO);
    }

    // Wait for parent to signal that it's finished.
    let mut event_buf = 0u64.to_ne_bytes();
    let nread = io::read(&from, &mut event_buf)?;
    if nread != size_of::<u64>() || u64::from_ne_bytes(event_buf) != 1 {
        return Err(Errno::IO);
    }
    // Close eventfd to not carry it across fork.
    // core::mem::drop(events);

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
    Ok(())
}

#[cold]
fn from_io_error(e: std::io::Error) -> Errno {
    Errno::from_io_error(&e).unwrap_or(Errno::IO)
}
