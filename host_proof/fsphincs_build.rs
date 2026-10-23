use std::{env, fs, path::Path};

/// Loads the canonical six-set registry and emits matching Rust/C parameters.
pub fn configure(header: &str, sphincs_params: &str) -> (String, String) {
    println!("cargo:rerun-if-changed={header}");
    println!("cargo:rerun-if-env-changed=FSPHINCS_PARAMS");
    for legacy in ["FSPHINCS_K", "FSPHINCS_SECURITY"] {
        println!("cargo:rerun-if-env-changed={legacy}");
        if env::var_os(legacy).is_some() {
            panic!("{legacy} is obsolete: select FSPHINCS_PARAMS=128s|128f|192s|192f|256s|256f");
        }
    }
    let paired = sphincs_params
        .rsplit('-')
        .next()
        .expect("SPHINCS parameter suffix");
    let name = env::var("FSPHINCS_PARAMS").unwrap_or_else(|_| paired.to_owned());
    let text = fs::read_to_string(header).expect("F-SPHINCS parameter registry");
    let prefix = format!("#define FS_PARAMS_{name} ");
    let row = text
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("unsupported FSPHINCS_PARAMS={name}"));
    let values: Vec<usize> = row.split(',').map(|s| s.trim().parse().unwrap()).collect();
    let [security, fast, d, k]: [usize; 4] = values.try_into().unwrap();
    if env::var("DAA_CREDENTIAL_SCHEME").as_deref() == Ok("fsphincs") && paired != name {
        panic!("F-SPHINCS credential and TPM security/profile must match: {name} != {paired}");
    }
    let node_bytes = security / 8;
    let h1_version = 6;
    let source = format!(
        "// Generated from parameter_sets.h; do not edit.\n\
         pub const K: usize = {k};\n\
         pub const D: usize = {d};\n\
         pub const NODE_BYTES: usize = {node_bytes};\n\
         pub const H1_VERSION: usize = {h1_version};\n\
         pub const MFORS_SIG_BYTES: usize = K * (32 + D * NODE_BYTES);\n\
         pub const ANCHORS: usize = {};\n",
        if security == 128 { 1 } else { 2 }
    );
    fs::write(
        Path::new(&env::var("OUT_DIR").unwrap()).join("fsphincs_params.rs"),
        source,
    )
    .expect("generated F-SPHINCS Rust constants");
    for (key, value) in [
        ("PARAMS", name.clone()),
        ("SECURITY", security.to_string()),
        ("K", k.to_string()),
        ("D", d.to_string()),
        ("FAST", fast.to_string()),
        ("NODE_BYTES", node_bytes.to_string()),
        ("H1_VERSION", h1_version.to_string()),
    ] {
        println!("cargo:rustc-env=FSPHINCS_{key}={value}");
    }
    (name, security.to_string())
}
