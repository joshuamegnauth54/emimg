use std::{fs, path::Path};

use spirv_builder::{ShaderPanicStrategy, SpirvBuilder};

fn build_spirv(path: impl AsRef<Path>, name: &str) {
    let metadata = SpirvBuilder::new(path, "spirv-unknown-vulkan1.3")
        .shader_panic_strategy(ShaderPanicStrategy::DebugPrintfThenExit {
            print_inputs: true,
            print_backtrace: true,
        })
        .build()
        .unwrap_or_else(|e| panic!("Failed building shader: {name}\nError: {e}"));
    println!(
        "cargo::rustc-env={}={}",
        name,
        metadata
            .module
            .unwrap_single()
            .to_str()
            .expect("Final path should be UTF-8")
    );
}

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    let shaders = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("Build with Cargo to ensure path env vars exist")
        .join("rust_shaders");
    println!("cargo::rerun-if-changed={}", shaders.to_str().unwrap());

    for shader in fs::read_dir(shaders).expect("shaders directory should be in root") {
        let shader = shader.expect("should be able to read/access shader directory");
        assert!(
            shader.file_type().unwrap().is_dir(),
            "shaders directory should only have directories"
        );
        let path = shader.path();
        let name = shader.file_name().to_ascii_uppercase();
        let name = name.to_str().unwrap();
        build_spirv(path, name);
    }

    #[cfg(feature = "no-libc")]
    println!("cargo::rustc-link-arg=-nostartfiles")
}
