use std::fs::{self, File, FileTimes};
use std::path::PathBuf;

// Implements main.
fn main() {
    for path in [
        "guest/Cargo.toml",
        "guest/Cargo.lock",
        "guest/build.rs",
        "../fsphincs_build.rs",
        "../rijndael.rs",
        "guest/src",
        "guest/c_src",
        "../../Cargo.toml",
        "../../Cargo.lock",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }
    for name in [
        "SPHINCS_PARAMS",
        "SPHINCS_THASH",
        "DAA_HOST_SCHEME",
        "DAA_TPM_BACKEND",
        "DAA_TPM_SHA_SCHEME",
        "DAA_CREDENTIAL_SCHEME",
        "FSPHINCS_PARAMS",
        "FSPHINCS_SECURITY",
        "FSPHINCS_K",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    let methods_rs = PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("methods.rs");
    let previous = fs::read(&methods_rs).ok().zip(
        fs::metadata(&methods_rs)
            .and_then(|metadata| metadata.modified())
            .ok(),
    );

    risc0_build::embed_methods();

    if let Some((bytes, modified)) = previous {
        if fs::read(&methods_rs).unwrap() == bytes {
            File::options()
                .write(true)
                .open(&methods_rs)
                .unwrap()
                .set_times(FileTimes::new().set_modified(modified))
                .unwrap();
        }
    }
    println!("cargo:rustc-env=METHODS_RS={}", methods_rs.display());
}
