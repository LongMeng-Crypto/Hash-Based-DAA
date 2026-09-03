use std::path::PathBuf;

// Configures C builds for the vendored TPM FAEST/AES sources.
fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let daa_full = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("daa_core should live under DAA_FULL/crates/daa_core")
        .to_path_buf();
    let tpm = daa_full.join("vendor/TPM_AES");
    let tpm_build = tpm.join("builddir_rel");
    let tpm_sha = daa_full.join("vendor/TPM_SHA");

    println!("cargo:rerun-if-changed=c_src/daa_tpm_shim.c");
    println!("cargo:rerun-if-changed={}", tpm.display());
    println!("cargo:rerun-if-changed={}", tpm_sha.display());

    build_tpm(&tpm, &tpm_build);
    build_tpm_sha(&tpm_sha);
}

/// Builds the independent C++ VOLEith TPM-SHA backend next to legacy TPM_AES.
fn build_tpm_sha(tpm: &PathBuf) {
    let faest = tpm.join("third_party/faest");
    let prefix_header = tpm.join("include/tpm_sha_faest_prefix.h");
    let mut c = base_c_build();
    c.define("FAEST_TESTS", None);
    c.flag("-include");
    c.flag(prefix_header.to_str().expect("UTF-8 TPM_SHA path"));
    c.flag_if_supported("-fvisibility=hidden");
    c.include(&faest);
    c.include(faest.join("sha3"));
    c.include(faest.join("sha3/opt64"));
    for file in [
        "aes.c",
        "bavc.c",
        "compat.c",
        "fields.c",
        "faest_aes_128.c",
        "instances.c",
        "random_oracle.c",
        "universal_hashing.c",
        "utils.c",
        "vole.c",
        "sha3/KeccakHash.c",
        "sha3/KeccakSponge.c",
        "sha3/opt64/KeccakP-1600-opt64.c",
    ] {
        c.file(faest.join(file));
    }
    c.compile("daa_tpm_sha_faest");

    let mut cpp = cc::Build::new();
    cpp.cpp(true);
    cpp.opt_level(3);
    cpp.warnings(false);
    cpp.flag_if_supported("-std=c++20");
    cpp.define("FAEST_STATIC", None);
    cpp.define("FAEST_EXPORT", Some(""));
    cpp.define("FAEST_TESTS", None);
    cpp.flag("-include");
    cpp.flag(prefix_header.to_str().expect("UTF-8 TPM_SHA path"));
    cpp.flag_if_supported("-fvisibility=hidden");
    cpp.include(tpm);
    cpp.include(tpm.join("include"));
    cpp.include(tpm.join("backend"));
    cpp.include(tpm.join("backend/vole"));
    cpp.include(tpm.join("circuits/sha256"));
    cpp.include(&faest);
    cpp.include(faest.join("sha3"));
    cpp.include(faest.join("sha3/opt64"));
    for file in [
        "backend/binary_circuit.cpp",
        "backend/backend_witness.cpp",
        "backend/prepared_binary_circuit.cpp",
        "backend/circuit_format.cpp",
        "backend/security_parameters.cpp",
        "backend/quadratic_relation.cpp",
        "backend/vole/gf128.cpp",
        "backend/vole/bit_matrix_transpose.cpp",
        "backend/generic_quicksilver.cpp",
        "backend/generic_nizk.cpp",
        "backend/vole/faest_vole.cpp",
        "backend/vole/quicksilver.cpp",
        "circuits/common/input_visibility.cpp",
        "circuits/sha256/sha256_core.cpp",
        "circuits/sha2/sha512_family.cpp",
        "src/tpm_sha_relation.cpp",
        "src/tpm_sha.cpp",
    ] {
        cpp.file(tpm.join(file));
    }
    cpp.compile("daa_tpm_sha");
    println!("cargo:rustc-link-lib=crypto");
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
