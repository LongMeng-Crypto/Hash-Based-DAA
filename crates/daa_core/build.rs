use std::path::PathBuf;

// Configures C builds for TPM FAEST and SPHINCS+ FFI.
fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let repo = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .expect("daa_core should live under DAA_FULL/crates/daa_core")
        .to_path_buf();
    let tpm = repo.join("TPM_AES");
    let tpm_build = tpm.join("builddir_rel");

    println!("cargo:rerun-if-changed=c_src/daa_tpm_shim.c");
    println!("cargo:rerun-if-changed={}", tpm.display());

    build_tpm(&tpm, &tpm_build);
}

// Creates the common C compiler configuration for FAEST sources.
fn base_c_build() -> cc::Build {
    let mut build = cc::Build::new();
    build.opt_level(3);
    build.warnings(false);
    build.define("FAEST_STATIC", None);
    build.define("FAEST_EXPORT", Some(""));
    build
}

// Compiles the TPM AES/FAEST sources needed by all six proof paths.
fn build_tpm(tpm: &PathBuf, tpm_build: &PathBuf) {
    let mut build = base_c_build();
    build.include(tpm);
    build.include(tpm_build);
    build.include(tpm.join("sha3"));
    build.include(tpm.join("sha3/opt64"));
    build.file("c_src/daa_tpm_shim.c");

    for file in [
        "compat.c",
        "fields.c",
        "random_oracle.c",
        "universal_hashing.c",
        "instances.c",
        "bavc.c",
        "daa_faest.c",
        "randomness.c",
        "owf.c",
        "cpu.c",
        "faest_impl.c",
        "vole.c",
        "utils.c",
        "aes.c",
    ] {
        build.file(tpm.join(file));
    }

    for file in [
        "faest_aes_128.c",
        "faest_aes_192.c",
        "faest_aes_256.c",
        "faest_128s.c",
        "faest_128f.c",
        "faest_192s.c",
        "faest_192f.c",
        "faest_256s.c",
        "faest_256f.c",
    ] {
        build.file(tpm_build.join(file));
    }

    for file in [
        "KeccakHash.c",
        "KeccakHashtimes4.c",
        "KeccakSponge.c",
        "KeccakSpongetimes4.c",
        "opt64/KeccakP-1600-opt64.c",
        "opt64/KeccakP-1600-times4-on1.c",
    ] {
        build.file(tpm.join("sha3").join(file));
    }

    build.compile("daa_tpm_faest_128s");
}
