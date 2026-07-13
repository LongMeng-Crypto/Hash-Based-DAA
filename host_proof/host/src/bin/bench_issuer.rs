// Benchmark runner for the DAA Issuer Setup phase only (no zkVM proving).
// Loops over all SPHINCS+ SHA-2 parameter sets and measures:
//   - KeyGen time
//   - Sign(msk, mpk) time
//   - Verify self-cert time
//   - Certificate signature size
//
// Run with: cargo run --bin bench_issuer --release

const VARIANTS: &[(&str, &str)] = &[
    ("sphincs-sha2-128s", "simple"),
    ("sphincs-sha2-128f", "simple"),
    ("sphincs-sha2-192s", "simple"),
    ("sphincs-sha2-192f", "simple"),
    ("sphincs-sha2-256s", "simple"),
    ("sphincs-sha2-256f", "simple"),
];

use std::process::Command;

fn main() {
    println!(
        "\n{:<24} {:>12} {:>12} {:>12} {:>12}",
        "Variant", "Keygen(ms)", "Sign(ms)", "Verify(ms)", "CertSize"
    );
    println!("{}", "-".repeat(76));

    for (params, thash) in VARIANTS {
        // Build issuer_setup binary for this parameter set.
        let build = Command::new("cargo")
            .args(["build", "--bin", "issuer_setup", "--release"])
            .env("SPHINCS_PARAMS", params)
            .env("SPHINCS_THASH", thash)
            .output()
            .expect("failed to spawn cargo build");

        if !build.status.success() {
            eprintln!(
                "BUILD FAILED {params}: {}",
                String::from_utf8_lossy(&build.stderr)
            );
            continue;
        }

        let output = Command::new("./target/release/issuer_setup")
            .env("SPHINCS_PARAMS", params)
            .env("SPHINCS_THASH", thash)
            .output()
            .expect("failed to run ./target/release/issuer_setup");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{}{}", stdout, stderr);

        if !output.status.success() {
            eprintln!("FAILED {params}: {combined}");
            continue;
        }

        let keygen_ms = parse_field(&combined, "keygen = ", " ms");
        let sign_ms = parse_field(&combined, "sign(msk, mpk) = ", " ms");
        let verify_ms = parse_field(&combined, "verify self-cert = ", " ms");
        let cert_size = parse_field(&combined, "cert sig size = ", " bytes");

        let cert_label = cert_size
            .parse::<u64>()
            .map(|b| format!("{:.0} KB", b as f64 / 1024.0))
            .unwrap_or(cert_size);

        println!(
            "{:<24} {:>12} {:>12} {:>12} {:>12}",
            params, keygen_ms, sign_ms, verify_ms, cert_label
        );
    }

    println!();
}

fn parse_field<'a>(text: &'a str, prefix: &str, suffix: &str) -> String {
    text.find(prefix)
        .and_then(|i| {
            let rest = &text[i + prefix.len()..];
            rest.find(suffix).map(|j| rest[..j].trim().to_string())
        })
        .unwrap_or_else(|| "?".to_string())
}
