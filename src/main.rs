// SPDX-License-Identifier: GPL-3.0-or-later

mod sandbox;
mod utils;

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn main() {
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();

    #[cfg(target_os = "linux")]
    // SAFETY: No threads, no shared file descriptors.
    unsafe {
        sandbox::sandbox_process(cap_std::ambient_authority()).unwrap()
    };

    // SANDBOX MOUNTS...

    #[cfg(not(target_os = "linux"))]
    compile_error!("Non-Linux operating systems are WIP");
}
