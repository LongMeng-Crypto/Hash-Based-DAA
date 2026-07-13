// Benchmark runner — edit VARIANTS to select which parameter sets to run.
// Run with: cargo run --bin bench_all --release

// ── Change these lines to select which variants to benchmark ──────────────────
const VARIANTS: &[(&str, &str)] = &[
    ("sphincs-sha2-128s", "simple"),
    ("sphincs-sha2-128f", "simple"),
    ("sphincs-sha2-192s", "simple"),
    ("sphincs-sha2-192f", "simple"),
    //("sphincs-sha2-256s", "simple"),
    //("sphincs-sha2-256f", "simple"),
];
// ─────────────────────────────────────────────────────────────────────────────

use std::process::Command;
use std::time::Instant;

fn main() {
    println!(
        "\n{:<20} {:>10} {:>10} {:>12} {:>12} {:>10}",
        "Variant", "Keygen(ms)", "Sign(ms)", "Prove(s)", "ProofSize", "Verify(ms)"
    );
    println!("{}", "-".repeat(76));

    for (params, thash) in VARIANTS {
        let t = Instant::now();

        // Build first so the binary reflects the correct SPHINCS_PARAMS C compilation.
        let build = Command::new("cargo")
            .args(["build", "--bin", "host", "--release"])
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

        // Run the binary directly to avoid cargo reusing a stale cached binary.
        let output = Command::new("./target/release/host")
            .env("SPHINCS_PARAMS", params)
            .env("SPHINCS_THASH", thash)
            .output()
            .expect("failed to run ./target/release/host");

        let elapsed = t.elapsed().as_secs();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{}{}", stdout, stderr);

        if !output.status.success() {
            eprintln!("FAILED {params}: {combined}");
            continue;
        }

        let keygen_ms = parse_field(&combined, "keygen = ", " ms");
        let sign_ms = parse_field(&combined, "signing = ", " ms");
        let prove_ms = parse_field(&combined, "prover time = ", " ms");
        let proof_size = parse_field(&combined, "proof size = ", " bytes");
        let verify_ms = parse_field(&combined, "verifier time = ", " ms");

        let proof_label = proof_size
            .parse::<u64>()
            .map(|b| format!("{:.0} KB", b as f64 / 1024.0))
            .unwrap_or(proof_size);

        let prove_s = prove_ms
            .parse::<f64>()
            .map(|ms| format!("{:.2}", ms / 1000.0))
            .unwrap_or(prove_ms);

        println!(
            "{:<20} {:>10} {:>10} {:>12} {:>12} {:>10}   (wall {}s)",
            params, keygen_ms, sign_ms, prove_s, proof_label, verify_ms, elapsed
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
