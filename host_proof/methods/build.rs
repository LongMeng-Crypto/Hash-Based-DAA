use std::fs::{self, File, FileTimes};
use std::path::PathBuf;

/// Embeds changed guests while keeping identical generated methods cache-stable.
fn main() {
    for path in [
        "guest/Cargo.toml",
        "guest/Cargo.lock",
        "guest/build.rs",
        "../fsphincs_build.rs",
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
        "SPHINCS_PROFILE",
        "SPHINCS_OPT_LEVEL",
        "SPHINCS_OPT_128S",
        "SPHINCS_SKIP_AES_CHECK",
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

    // risc0-build watches its own output to force a rebuild on every invocation.
    // Restore only the timestamp of byte-identical output; source/lock/parameter
    // dependencies above still force rebuilding whenever the guest could change.
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
