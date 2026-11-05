#[path = "../../fsphincs_build.rs"]
mod fsphincs_build;
use std::env;
use std::path::Path;

// Implements main.
fn main() {
    println!("cargo:rerun-if-changed=../../protocol_context.rs");
    println!("cargo:rerun-if-changed=../../rijndael.rs");
    let dir = "c_src/sphincs_ref";
    if !Path::new(dir).exists() {
        panic!("C source dir not found: {}", dir);
    }

    let params = env::var("SPHINCS_PARAMS").unwrap_or_else(|_| "sphincs-sha2-128s".to_string());
    let thash = env::var("SPHINCS_THASH").unwrap_or_else(|_| "simple".to_string());
    let tpm_backend = env::var("DAA_TPM_BACKEND").unwrap_or_else(|_| "aes".to_string());
    if !matches!(tpm_backend.as_str(), "aes" | "sha2" | "rijndael") {
        panic!("DAA_TPM_BACKEND must be aes, rijndael, or sha2");
    }
    let tpm_sha_scheme = env::var("DAA_TPM_SHA_SCHEME").unwrap_or_else(|_| "ours".to_string());
    if tpm_sha_scheme != "ours" && tpm_sha_scheme != "chen23" {
        panic!("DAA_TPM_SHA_SCHEME must be ours or chen23");
    }
    if tpm_backend != "sha2" && tpm_sha_scheme != "ours" {
        panic!("DAA_TPM_SHA_SCHEME=chen23 requires DAA_TPM_BACKEND=sha2");
    }
    let (fs_params, fs_security) =
        fsphincs_build::configure("c_src/fsphincs_ref/parameter_sets.h", &params);
    const VALID_PARAMS: &[&str] = &[
        "sphincs-sha2-128s",
        "sphincs-sha2-128f",
        "sphincs-sha2-192s",
        "sphincs-sha2-192f",
        "sphincs-sha2-256s",
        "sphincs-sha2-256f",
    ];
    assert!(
        VALID_PARAMS.contains(&params.as_str()),
        "unsupported SHA2 credential parameters"
    );
    assert_eq!(
        thash, "simple",
        "only SHA2-simple credentials are supported"
    );
    let hash_backend = "sha2";
    let credential_scheme = env::var("DAA_CREDENTIAL_SCHEME").unwrap_or_else(|_| "sphincs".into());
    let host_scheme = env::var("DAA_HOST_SCHEME").unwrap_or_else(|_| {
        if credential_scheme == "fsphincs" {
            "fsphincs"
        } else {
            "recursive-zk"
        }
        .to_string()
    });
    assert!(
        matches!(
            host_scheme.as_str(),
            "recursive-zk" | "zk-wots" | "fsphincs"
        ),
        "unsupported Host construction"
    );
    assert_eq!(
        host_scheme == "fsphincs",
        credential_scheme == "fsphincs",
        "Host construction and credential family must match"
    );

    let params_header = format!("{}/params/params-{}.h", dir, params);
    if !Path::new(&params_header).exists() {
        panic!("Params header not found: {}", params_header);
    }

    let core_files: &[&str] = &["verify_recursive.c", "address.c", "utils.c"];

    let backend_files: &[&str] = &["sha2.c", "hash_sha2.c"];

    let thash_file = format!("thash_{}_{}.c", hash_backend, thash);

    let mut build = cc::Build::new();
    build.include(dir);
    build.include(format!("{}/params", dir));
    build.define("PARAMS", params.as_str());
    if hash_backend == "sha2" && thash == "simple" {
        build.define("DAA_WOTS_SUPPORTED", None);
    }
    build.opt_level(3);
    build.warnings(false);

    build.define("RISC0_SHA_SYSCALL", None);
    build.define("DAA_SHA256_SYSCALL", None);
    build.define("DAA_SPHINCS_VERIFY", None);
    if host_scheme == "zk-wots" {
        build.define("DAA_ZK_WOTS", None);
    }

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
    build.file(format!("{}/issuer_wots_verify.c", dir));

    let fs_dir = "c_src/fsphincs_ref";
    let mut fs_build = cc::Build::new();
    fs_build
        .define("RISC0_SHA_SYSCALL", None)
        .include(fs_dir)
        .include(dir)
        .define("FSPHINCS_VERIFY_ONLY", None)
        .define("FSPHINCS_PARAMS", fs_params.as_str())
        .opt_level(3)
        .warnings(true)
        .file(format!("{}/fsphincs.c", fs_dir))
        .compile("fsphincs_ref");
    println!("cargo:rerun-if-changed={}", fs_dir);

    build.compile("sphincs_ref");

    println!("cargo:rerun-if-changed={}", dir);
    println!("cargo:rerun-if-changed={}", params_header);
    println!("cargo:rerun-if-env-changed=DAA_HOST_SCHEME");
    println!("cargo:rustc-env=DAA_HOST_SCHEME={}", host_scheme);
    println!("cargo:rerun-if-env-changed=SPHINCS_PARAMS");
    println!("cargo:rerun-if-env-changed=SPHINCS_THASH");
    println!("cargo:rerun-if-env-changed=DAA_CREDENTIAL_SCHEME");
    println!("cargo:rerun-if-env-changed=DAA_TPM_BACKEND");
    println!("cargo:rerun-if-env-changed=DAA_TPM_SHA_SCHEME");
    println!("cargo:rerun-if-env-changed=FSPHINCS_SECURITY");
    println!("cargo:rerun-if-env-changed=FSPHINCS_K");

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
    let (spx_pk_bytes, spx_sig_bytes) = match params.as_str() {
        "sphincs-sha2-128s" => ("32", "7856"),
        "sphincs-sha2-128f" => ("32", "17088"),
        "sphincs-sha2-192s" => ("48", "16224"),
        "sphincs-sha2-192f" => ("48", "35664"),
        "sphincs-sha2-256s" => ("64", "29792"),
        "sphincs-sha2-256f" => ("64", "49856"),
        _ => unreachable!(),
    };
    println!("cargo::rustc-check-cfg=cfg(lambda_128)");
    println!("cargo::rustc-check-cfg=cfg(lambda_192)");
    println!("cargo::rustc-check-cfg=cfg(lambda_256)");
    println!("cargo::rustc-check-cfg=cfg(daa_tpm_rijndael)");
    if tpm_backend == "rijndael" {
        assert!(
            params.contains("128"),
            "Rijndael-256 VOLEith supports 128s/128f"
        );
        println!("cargo:rustc-cfg=daa_tpm_rijndael");
    }
    println!("cargo::rustc-check-cfg=cfg(daa_tpm_sha2)");
    println!("cargo::rustc-check-cfg=cfg(daa_tpm_sha_chen23)");
    println!("cargo::rustc-check-cfg=cfg(fsphincs_192)");
    println!("cargo::rustc-check-cfg=cfg(fsphincs_256)");
    println!("cargo:rustc-cfg=lambda_{}", sec_level);
    if tpm_backend == "sha2" {
        println!("cargo:rustc-cfg=daa_tpm_sha2");
    }
    if tpm_sha_scheme == "chen23" {
        println!("cargo:rustc-cfg=daa_tpm_sha_chen23");
    }
    match fs_security.as_str() {
        "192" => println!("cargo:rustc-cfg=fsphincs_192"),
        "256" => println!("cargo:rustc-cfg=fsphincs_256"),
        _ => {}
    }

    println!("cargo:rustc-env=SPHINCS_N={}", spx_n);
    println!("cargo:rustc-env=SPHINCS_PK_BYTES={}", spx_pk_bytes);
    println!("cargo:rustc-env=SPHINCS_SIG_BYTES={}", spx_sig_bytes);

    println!("cargo:rustc-env=SPHINCS_PARAMS={}", params);
    println!("cargo:rustc-env=SPHINCS_THASH={}", thash);
    println!("cargo:rustc-env=SPHINCS_HASH_BACKEND={}", hash_backend);
    println!("cargo:rustc-env=FSPHINCS_SECURITY={}", fs_security);
    println!("cargo:rustc-env=DAA_TPM_BACKEND={}", tpm_backend);
    println!("cargo:rustc-env=DAA_TPM_SHA_SCHEME={}", tpm_sha_scheme);
}
