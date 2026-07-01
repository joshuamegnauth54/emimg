fn main() {
    #[cfg(feature = "no-libc")]
    println!("cargo:rustc-link-arg=-nostartfiles")
}
