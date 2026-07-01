// SPDX-License-Identifier: GPL-3.0-or-later

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[cfg(target_os = "linux")]
fn linux_sandbox() {
    // SAFETY: No threads, no shared file descriptors.
    unsafe { emimg_sandbox::sandbox_process(cap_std::ambient_authority()).unwrap() };
}

fn main() {
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();

    #[cfg(target_os = "linux")]
    linux_sandbox();

    // SANDBOX MOUNTS...

    #[cfg(not(target_os = "linux"))]
    compile_error!("Non-Linux operating systems are WIP");
}
