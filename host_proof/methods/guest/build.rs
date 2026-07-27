use std::env;
use std::path::Path;

fn main() {
    let dir = "c_src/sphincs_ref";
    if !Path::new(dir).exists() {
        panic!("C source dir not found: {}", dir);
    }

    // -----------------------------------------------------------------------
    // Parameter set selection
    //
    // Set SPHINCS_PARAMS in the environment before building to choose a
    // parameter set.  Default: sphincs-sha2-128s
    //
    // Valid values (18 parameter sets):
    //   SHA-2 based (SHA-256 syscall-accelerated on RISC-V for 128/192):
    //     sphincs-sha2-128f  sphincs-sha2-128s   <- fastest on RISC-V (SHA-256)
    //     sphincs-sha2-192f  sphincs-sha2-192s   <- SHA-256 for PRF, SHA-512 for thash
    //     sphincs-sha2-256f  sphincs-sha2-256s   <- SHA-512 dominant (software)
    //
    //   SHAKE based (Keccak-p[1600], 64-bit lanes, software on RISC-V):
    //     sphincs-shake-128f sphincs-shake-128s
    //     sphincs-shake-192f sphincs-shake-192s
    //     sphincs-shake-256f sphincs-shake-256s
    //
    //   Haraka based (bit-sliced software AES, portable):
    //     sphincs-haraka-128f sphincs-haraka-128s
    //     sphincs-haraka-192f sphincs-haraka-192s
    //     sphincs-haraka-256f sphincs-haraka-256s
    //
    // Tweakable-hash variant selection via SPHINCS_THASH:
    //   simple  (default) - no bitmask step, ~30% faster thash calls
    //   robust            - MGF1 bitmask, stronger non-malleability guarantee
    // -----------------------------------------------------------------------

    let params = env::var("SPHINCS_PARAMS")
        .unwrap_or_else(|_| "sphincs-sha2-128s".to_string());
    let thash = env::var("SPHINCS_THASH")
        .unwrap_or_else(|_| "simple".to_string());
    let profile = env::var("SPHINCS_PROFILE").unwrap_or_default() == "1";
    let fs_security = env::var("FSPHINCS_SECURITY")
        .unwrap_or_else(|_| "128".to_string());
    if fs_security != "128" && fs_security != "256" {
        panic!("FSPHINCS_SECURITY must be 128 or 256");
    }
    let skip_aes = env::var("SPHINCS_SKIP_AES_CHECK").unwrap_or_default() == "1";
    let opt_level_from_new = env::var("SPHINCS_OPT_LEVEL")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);
    let opt_level_from_compat = env::var("SPHINCS_OPT_128S")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);
    let opt_level = opt_level_from_new.max(opt_level_from_compat);
    let opt_128_sha256_glue = opt_level > 0;

    // Validate params
    const VALID_PARAMS: &[&str] = &[
        "sphincs-sha2-128f",   "sphincs-sha2-128s",
        "sphincs-sha2-192f",   "sphincs-sha2-192s",
        "sphincs-sha2-256f",   "sphincs-sha2-256s",
        "sphincs-shake-128f",  "sphincs-shake-128s",
        "sphincs-shake-192f",  "sphincs-shake-192s",
        "sphincs-shake-256f",  "sphincs-shake-256s",
        "sphincs-haraka-128f", "sphincs-haraka-128s",
        "sphincs-haraka-192f", "sphincs-haraka-192s",
        "sphincs-haraka-256f", "sphincs-haraka-256s",
    ];
    if !VALID_PARAMS.contains(&params.as_str()) {
        panic!(
            "Invalid SPHINCS_PARAMS='{}'. Valid values:\n  {}",
            params,
            VALID_PARAMS.join("\n  ")
        );
    }
    if thash != "simple" && thash != "robust" {
        panic!("Invalid SPHINCS_THASH='{}'. Must be 'simple' or 'robust'.", thash);
    }
    if opt_level > 0 && (!params.contains("-sha2-") || thash != "simple") {
        panic!("SPHINCS_OPT_LEVEL/SPHINCS_OPT_128S requires a SHA2 parameter set and SPHINCS_THASH=simple");
    }
    if opt_level == 1 && !params.contains("-128") {
        panic!("SPHINCS_OPT_LEVEL=1 is only meaningful for SHA2-128s/f; use SPHINCS_OPT_LEVEL=2 for SHA2-192/256");
    }

    // Derive hash backend
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

    // -----------------------------------------------------------------------
    // Explicit file lists — avoids duplicate-symbol bugs from glob inclusion
    // -----------------------------------------------------------------------

    // Core files used by every backend
    let core_files: &[&str] = if opt_level >= 2 {
        &[
            "sign_verify_128s_opt.c",
            "utils.c",
            "prf_wrapper.c",
            "sphincs_profile.c",
            "wots_extreme.c",
        ]
    } else {
        &[
            "sign_verify.c",
            "address.c",
            "fors_verify.c",
            "wots_verify.c",
            "utils.c",
            "prf_wrapper.c",
            "sphincs_profile.c",
            "wots_extreme.c",
        ]
    };

    // Backend-specific implementation files
    let backend_files: &[&str] = match hash_backend {
        "sha2"   => &["sha2.c", "hash_sha2.c"],
        "shake"  => &["fips202.c", "hash_shake.c"],
        "haraka" => &["haraka.c", "hash_haraka.c"],
        _        => unreachable!(),
    };

    // Exactly one tweakable-hash file: thash_{backend}_{simple|robust}.c
    let thash_file = format!("thash_{}_{}.c", hash_backend, thash);

    // -----------------------------------------------------------------------
    // Configure and run the C compiler
    // -----------------------------------------------------------------------

    let mut build = cc::Build::new();
    build.include(dir);
    build.include(format!("{}/params", dir));
    build.define("PARAMS", params.as_str());
    build.opt_level(3);
    build.warnings(false);

    // Enable RISC0 SHA-256 syscall hook in sha2.c.
    // For shake/haraka backends sha2.c is not compiled, so this is a no-op.
    build.define("RISC0_SHA_SYSCALL", None);
    if profile {
        build.define("SPHINCS_PROFILE", None);
    }
    if opt_128_sha256_glue {
        build.define("SPHINCS_OPT_128S", None);
    }
    if opt_level >= 2 {
        build.define("SPHINCS_OPT_128S_LEVEL2", None);
    }
    if opt_level >= 3 && opt_level <= 4 {
        build.define("SPHINCS_OPT_ZK_WOTS", None);
    }
    if opt_level == 4 {
        build.define("SPHINCS_OPT_ZK_WOTS_FAST", None);
    }

    // Add all source files
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
        thash_path, hash_backend, thash
    );
    build.file(&thash_path);

    // F-SPHINCS+ guest archive: verification only. Host-only key generation,
    // signing, 2 MiB tree buffers, and randombytes references are excluded.
    // Compile before sphincs_ref so its SHA-256 references resolve from the
    // following archive under static link ordering.
    let fs_dir = "c_src/fsphincs_ref";
    let mut fs_build = cc::Build::new();
    fs_build
        .include(fs_dir)
        .include(dir)
        .define("FSPHINCS_VERIFY_ONLY", None)
        .define("FSPHINCS_SECURITY", fs_security.as_str())
        .opt_level(3)
        .warnings(true)
        .file(format!("{}/fsphincs.c", fs_dir))
        .compile("fsphincs_ref");
    println!("cargo:rerun-if-changed={}", fs_dir);

    build.compile("sphincs_ref");

    // Rebuild triggers
    println!("cargo:rerun-if-changed={}", dir);
    println!("cargo:rerun-if-changed={}", params_header);
    println!("cargo:rerun-if-env-changed=SPHINCS_PARAMS");
    println!("cargo:rerun-if-env-changed=SPHINCS_THASH");
    println!("cargo:rerun-if-env-changed=SPHINCS_PROFILE");
    println!("cargo:rerun-if-env-changed=SPHINCS_OPT_LEVEL");
    println!("cargo:rerun-if-env-changed=SPHINCS_OPT_128S");
    println!("cargo:rerun-if-env-changed=SPHINCS_SKIP_AES_CHECK");
    println!("cargo:rerun-if-env-changed=FSPHINCS_SECURITY");

    // Security level → cfg flag + SPHINCS_N byte count
    let sec_level = if params.contains("-128") { "128" }
        else if params.contains("-192") { "192" }
        else { "256" };
    let spx_n = if params.contains("-128") { "16" }
        else if params.contains("-192") { "24" }
        else { "32" };
    let (spx_pk_bytes, spx_sig_bytes) = match params.as_str() {
        "sphincs-sha2-128s" | "sphincs-shake-128s" | "sphincs-haraka-128s" => ("32", "7856"),
        "sphincs-sha2-128f" | "sphincs-shake-128f" | "sphincs-haraka-128f" => ("32", "17088"),
        "sphincs-sha2-192s" | "sphincs-shake-192s" | "sphincs-haraka-192s" => ("48", "16224"),
        "sphincs-sha2-192f" | "sphincs-shake-192f" | "sphincs-haraka-192f" => ("48", "35664"),
        "sphincs-sha2-256s" | "sphincs-shake-256s" | "sphincs-haraka-256s" => ("64", "29792"),
        "sphincs-sha2-256f" | "sphincs-shake-256f" | "sphincs-haraka-256f" => ("64", "49856"),
        _ => unreachable!(),
    };
    println!("cargo::rustc-check-cfg=cfg(lambda_128)");
    println!("cargo::rustc-check-cfg=cfg(lambda_192)");
    println!("cargo::rustc-check-cfg=cfg(lambda_256)");
    println!("cargo::rustc-check-cfg=cfg(sphincs_profile)");
    println!("cargo::rustc-check-cfg=cfg(skip_aes_check)");
    println!("cargo::rustc-check-cfg=cfg(sphincs_opt5_padding)");
    println!("cargo::rustc-check-cfg=cfg(fsphincs_256)");
    println!("cargo:rustc-cfg=lambda_{}", sec_level);
    if profile {
        println!("cargo:rustc-cfg=sphincs_profile");
    }
    if skip_aes {
        println!("cargo:rustc-cfg=skip_aes_check");
    }
    if opt_level == 5 {
        println!("cargo:rustc-cfg=sphincs_opt5_padding");
    }
    if fs_security == "256" {
        println!("cargo:rustc-cfg=fsphincs_256");
    }

    let default_opt5_pad_blocks = if opt_level == 5 {
        match params.as_str() {
            // These defaults target a single visible segment-size bin for the
            // estimated WOTS min/max range. They can be tuned without code
            // changes via SPHINCS_OPT5_PAD_BLOCKS.
            "sphincs-sha2-128s" => "4500",
            "sphincs-sha2-128f" => "52000",
            "sphincs-sha2-192s" => "11000",
            "sphincs-sha2-192f" => "39000",
            "sphincs-sha2-256s" => "0",
            "sphincs-sha2-256f" => "25000",
            _ => "0",
        }
    } else {
        "0"
    };
    let opt5_pad_blocks = env::var("SPHINCS_OPT5_PAD_BLOCKS")
        .unwrap_or_else(|_| default_opt5_pad_blocks.to_string());
    println!("cargo:rerun-if-env-changed=SPHINCS_OPT5_PAD_BLOCKS");

    println!("cargo:rustc-env=SPHINCS_N={}", spx_n);
    println!("cargo:rustc-env=SPHINCS_PK_BYTES={}", spx_pk_bytes);
    println!("cargo:rustc-env=SPHINCS_SIG_BYTES={}", spx_sig_bytes);

    // Expose selections to guest Rust code via env!() macro
    println!("cargo:rustc-env=SPHINCS_PARAMS={}", params);
    println!("cargo:rustc-env=SPHINCS_THASH={}", thash);
    println!("cargo:rustc-env=SPHINCS_HASH_BACKEND={}", hash_backend);
    println!("cargo:rustc-env=SPHINCS_PROFILE={}", if profile { "1" } else { "0" });
    println!("cargo:rustc-env=SPHINCS_OPT_LEVEL={}", opt_level);
    println!("cargo:rustc-env=SPHINCS_OPT_128S={}", opt_level);
    println!("cargo:rustc-env=SPHINCS_OPT5_PAD_BLOCKS={}", opt5_pad_blocks);
    println!("cargo:rustc-env=SPHINCS_SKIP_AES_CHECK={}", if skip_aes { "1" } else { "0" });
    println!("cargo:rustc-env=FSPHINCS_SECURITY={}", fs_security);
}
