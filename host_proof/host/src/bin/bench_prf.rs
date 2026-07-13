// Benchmark runner — DAA FORS sk_i PRF Proof only.
// Proves: sk_i = prf_addr(SK.seed, PK.seed, ADRS) for one FORS leaf.
//
// Only 3 variants (one per security level): s/f trade-off is irrelevant
// because we prove a single SHA-256 hash call regardless of the full
// SPHINCS+ tree structure.
//
// CPU: cargo run --bin bench_prf --release
// GPU: cargo run --bin bench_prf --release --features cuda

const VARIANTS: &[(&str, &str)] = &[
    ("sphincs-sha2-128s", "simple"),
    ("sphincs-sha2-192s", "simple"),
    ("sphincs-sha2-256s", "simple"),
];

use std::process::Command;
use std::time::Instant;

fn main() {
    println!(
        "\n{:<24} {:>10} {:>10} {:>12} {:>14} {:>14} {:>9}",
        "Variant", "Prove(s)", "ProofSize", "Verify(ms)", "UserCycles", "TotalCycles", "Segments"
    );
    println!("{}", "-".repeat(102));

    for (params, thash) in VARIANTS {
        let t = Instant::now();

        let mut build_cmd = Command::new("cargo");
        build_cmd.args(["build", "--bin", "prf_only", "--release"]);
        if cfg!(feature = "cuda") {
            build_cmd.args(["--features", "cuda"]);
        }
        let build = build_cmd
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

        // Forward guest build output to stderr so the user can see progress.
        eprint!("{}", String::from_utf8_lossy(&build.stderr));

        let output = Command::new("./target/release/prf_only")
            .env("SPHINCS_PARAMS", params)
            .env("SPHINCS_THASH", thash)
            .env("RISC0_PROVER", "local")
            .output()
            .expect("failed to run ./target/release/prf_only");

        let elapsed = t.elapsed().as_secs();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{}{}", stdout, stderr);

        if !output.status.success() {
            eprintln!("FAILED {params}: {combined}");
            continue;
        }

        let prove_ms = parse_field(&combined, "prf prover time = ", " ms");
        let proof_size = parse_field(&combined, "prf proof size = ", " bytes");
        let verify_ms = parse_field(&combined, "prf verifier time = ", " ms");
        let user_cycles = parse_field(&combined, "user=", " total=");
        let total_cycles = parse_field(&combined, "total=", " paging=");
        let segments = parse_field(&combined, "segments=", "\n");

        let proof_label = proof_size
            .parse::<u64>()
            .map(|b| format!("{:.0} KB", b as f64 / 1024.0))
            .unwrap_or(proof_size);

        let prove_s = prove_ms
            .parse::<f64>()
            .map(|ms| format!("{:.2}", ms / 1000.0))
            .unwrap_or(prove_ms);

        println!(
            "{:<24} {:>10} {:>10} {:>12} {:>14} {:>14} {:>9}   (wall {}s)",
            params, prove_s, proof_label, verify_ms, user_cycles, total_cycles, segments, elapsed
        );
    }

    println!();
}

fn parse_field(text: &str, prefix: &str, suffix: &str) -> String {
    text.find(prefix)
        .and_then(|i| {
            let rest = &text[i + prefix.len()..];
            rest.find(suffix).map(|j| rest[..j].trim().to_string())
        })
        .unwrap_or_else(|| "?".to_string())
}
