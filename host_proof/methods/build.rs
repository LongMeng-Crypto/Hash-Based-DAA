use std::path::PathBuf;

fn main() {
    // 触发重建：guest / C 代码改了就重新生成 methods.rs
    println!("cargo:rerun-if-changed=guest/Cargo.toml");
    println!("cargo:rerun-if-changed=guest/src");
    println!("cargo:rerun-if-changed=guest/src/bin");
    println!("cargo:rerun-if-changed=guest/c_src");

    // 让 risc0-build 生成 (OUT_DIR)/methods.rs，并编译/嵌入 guest ELF
    risc0_build::embed_methods();

    // Cargo 的 OUT_DIR 只对 build.rs 可见；我们把 methods.rs 的路径注入给 rustc 编译期
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let methods_rs = out_dir.join("methods.rs");
    println!("cargo:rustc-env=METHODS_RS={}", methods_rs.display());
}
