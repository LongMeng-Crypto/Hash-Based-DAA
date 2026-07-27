use std::env;
use std::path::Path;

fn main() {
    let dir = "../methods/guest/c_src/sphincs_ref";
    if !Path::new(dir).exists() {
        panic!("C source dir not found: {}", dir);
    }

    // Must match the selection in methods/guest/build.rs.
    // Both are driven by the same environment variables.
    let params = env::var("SPHINCS_PARAMS").unwrap_or_else(|_| "sphincs-sha2-128s".to_string());
    let thash = env::var("SPHINCS_THASH").unwrap_or_else(|_| "simple".to_string());
    let profile = env::var("SPHINCS_PROFILE").unwrap_or_default() == "1";
    let fs_security = env::var("FSPHINCS_SECURITY")
        .unwrap_or_else(|_| "128".to_string());
    if fs_security != "128" && fs_security != "256" {
        panic!("FSPHINCS_SECURITY must be 128 or 256");
    }

    const VALID_PARAMS: &[&str] = &[
        "sphincs-sha2-128f",
        "sphincs-sha2-128s",
        "sphincs-sha2-192f",
        "sphincs-sha2-192s",
        "sphincs-sha2-256f",
        "sphincs-sha2-256s",
        "sphincs-shake-128f",
        "sphincs-shake-128s",
        "sphincs-shake-192f",
        "sphincs-shake-192s",
        "sphincs-shake-256f",
        "sphincs-shake-256s",
        "sphincs-haraka-128f",
        "sphincs-haraka-128s",
        "sphincs-haraka-192f",
        "sphincs-haraka-192s",
        "sphincs-haraka-256f",
        "sphincs-haraka-256s",
    ];
    if !VALID_PARAMS.contains(&params.as_str()) {
        panic!(
            "Invalid SPHINCS_PARAMS='{}'. Valid values:\n  {}",
            params,
            VALID_PARAMS.join("\n  ")
        );
    }
    if thash != "simple" && thash != "robust" {
        panic!(
            "Invalid SPHINCS_THASH='{}'. Must be 'simple' or 'robust'.",
            thash
        );
    }

    let hash_backend = if params.contains("-sha2-") {
        "sha2"
    } else if params.contains("-shake-") {
        "shake"
    } else {
        "haraka"
    };

    let params_header = format!("{}/params/params-{}.h", dir, params);
    if !Path::new(&params_header).exists() {
        panic!("Params header not found: {}", params_header);
    }

    let core_files: &[&str] = &[
        "sign.c",
        "address.c",
        "fors.c",
        "merkle.c",
        "wots.c",
        "wotsx1.c",
        "utils.c",
        "utilsx1.c",
        "prf_wrapper.c",
    ];

    let backend_files: &[&str] = match hash_backend {
        "sha2" => &["sha2.c", "hash_sha2.c"],
        "shake" => &["fips202.c", "hash_shake.c"],
        "haraka" => &["haraka.c", "hash_haraka.c"],
        _ => unreachable!(),
    };

    let thash_file = format!("thash_{}_{}.c", hash_backend, thash);

    let mut build = cc::Build::new();
    build.include(dir);
    build.include(format!("{}/params", dir));
    build.define("PARAMS", params.as_str());
    build.opt_level(3);
    build.warnings(false);

    // Host does NOT use RISC0 syscalls — compiles plain C SHA2 implementation
    build.file("c_src/sphincs_consts.c");

    for &f in core_files.iter().chain(backend_files.iter()) {
        let path = format!("{}/{}", dir, f);
        assert!(
            Path::new(&path).exists(),
            "Expected source file not found: {}",
            path
        );
        build.file(&path);
    }
    let thash_path = format!("{}/{}", dir, thash_file);
    assert!(
        Path::new(&thash_path).exists(),
        "thash file not found: {}  (hash_backend={}, thash={})",
        thash_path,
        hash_backend,
        thash
    );
    build.file(&thash_path);

    // Experimental F-SPHINCS+-SHA256 implementation from the PQCrypto 2023
    // hash-based DAA paper. It is compiled in parallel with SPHINCS+ and uses
    // the portable SHA-256 implementation linked immediately after it.
    // Compile this archive first so static-link ordering resolves its sha256
    // reference from sphincs_ref.
    let fs_dir = "../methods/guest/c_src/fsphincs_ref";
    let mut fs_build = cc::Build::new();
    fs_build
        .include(fs_dir)
        .include(dir)
        .define("FSPHINCS_SECURITY", fs_security.as_str())
        .opt_level(3)
        .warnings(true)
        .file(format!("{}/fsphincs.c", fs_dir))
        .file("c_src/fsphincs_consts.c")
        .compile("fsphincs_ref");
    println!("cargo:rerun-if-changed={}", fs_dir);

    build.compile("sphincs_ref");

    println!("cargo:rerun-if-changed={}", dir);
    println!("cargo:rerun-if-changed={}", params_header);
    println!("cargo:rerun-if-env-changed=SPHINCS_PARAMS");
    println!("cargo:rerun-if-env-changed=SPHINCS_THASH");
    println!("cargo:rerun-if-env-changed=SPHINCS_PROFILE");
    println!("cargo:rerun-if-env-changed=FSPHINCS_SECURITY");

    // Security level → cfg flag + SPHINCS_N byte count
    let sec_level = if params.contains("-128") {
        "128"
    } else if params.contains("-192") {
        "192"
    } else {
        "256"
    };
    let spx_n = if params.contains("-128") {
        "16"
    } else if params.contains("-192") {
        "24"
    } else {
        "32"
    };
    println!("cargo::rustc-check-cfg=cfg(lambda_128)");
    println!("cargo::rustc-check-cfg=cfg(lambda_192)");
    println!("cargo::rustc-check-cfg=cfg(lambda_256)");
    println!("cargo::rustc-check-cfg=cfg(sphincs_profile)");
    println!("cargo::rustc-check-cfg=cfg(fsphincs_256)");
    println!("cargo:rustc-cfg=lambda_{}", sec_level);
    if profile {
        println!("cargo:rustc-cfg=sphincs_profile");
    }
    if fs_security == "256" {
        println!("cargo:rustc-cfg=fsphincs_256");
    }
    println!("cargo:rustc-env=SPHINCS_N={}", spx_n);

    // Expose to host/src/main.rs via env!()
    println!("cargo:rustc-env=SPHINCS_PARAMS={}", params);
    println!("cargo:rustc-env=SPHINCS_THASH={}", thash);
    println!("cargo:rustc-env=SPHINCS_HASH_BACKEND={}", hash_backend);
    println!(
        "cargo:rustc-env=SPHINCS_PROFILE={}",
        if profile { "1" } else { "0" }
    );
    println!("cargo:rustc-env=FSPHINCS_SECURITY={}", fs_security);
}
