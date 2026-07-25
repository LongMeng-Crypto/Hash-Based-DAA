use std::time::Instant;

use methods::{WOTS_EXTREME_GUEST_ELF, WOTS_EXTREME_GUEST_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, ReceiptKind};

fn read_u32(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap())
}

fn run(mode: u32, seg_po2: u32, backend_hash: &str, real_proof: bool) {
    let env = ExecutorEnv::builder()
        .segment_limit_po2(seg_po2)
        .write(&mode)
        .unwrap()
        .build()
        .unwrap();

    let opts = if real_proof {
        ProverOpts::composite()
            .with_hashfn(backend_hash.to_string())
            .with_receipt_kind(ReceiptKind::Composite)
    } else {
        ProverOpts::fast()
    };

    let label = if mode == 0 {
        "min-root=ff"
    } else {
        "max-root=00"
    };
    println!(
        "[{}] start WOTS diagnostic (seg_po2={}, proof_mode={})",
        label,
        seg_po2,
        if real_proof { "real-composite" } else { "fast" }
    );

    let t0 = Instant::now();
    let prove_info = default_prover()
        .prove_with_opts(env, WOTS_EXTREME_GUEST_ELF, &opts)
        .unwrap();
    let elapsed_ms = t0.elapsed().as_millis();
    let stats = prove_info.stats.clone();
    let receipt = prove_info.receipt;

    let journal = receipt.journal.bytes.as_slice();
    assert_eq!(journal.len(), 24);
    let out_mode = read_u32(journal, 0);
    let n = read_u32(journal, 4);
    let d = read_u32(journal, 8);
    let wots_len = read_u32(journal, 12);
    let thash1_calls = read_u64(journal, 16);
    assert_eq!(out_mode, mode);

    if real_proof {
        receipt.verify(WOTS_EXTREME_GUEST_ID).unwrap();
    }
    let proof_bytes =
        risc0_zkvm::serde::to_vec(&receipt).unwrap().len() * core::mem::size_of::<u32>();

    println!(
        "[{}] params={} n={} d={} wots_len={} thash1_calls={} elapsed_ms={} proof_bytes={}",
        label,
        env!("SPHINCS_PARAMS"),
        n,
        d,
        wots_len,
        thash1_calls,
        elapsed_ms,
        proof_bytes
    );
    println!(
        "[{}] guest cycles: user={} total={} paging={} reserved={} segments={}",
        label,
        stats.user_cycles,
        stats.total_cycles,
        stats.paging_cycles,
        stats.reserved_cycles,
        stats.segments,
    );
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let seg_po2: u32 = std::env::var("RISC0_SEGMENT_LIMIT_PO2")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(21);
    let backend_hash =
        std::env::var("RISC0_BACKEND_HASH").unwrap_or_else(|_| "sha-256".to_string());
    let real_proof = std::env::var("WOTS_DIAG_REAL_PROOF").ok().as_deref() == Some("1");

    println!(
        "WOTS extreme diagnostic — params={} thash={} backend={} seg_po2={} mode={}",
        env!("SPHINCS_PARAMS"),
        env!("SPHINCS_THASH"),
        env!("SPHINCS_HASH_BACKEND"),
        seg_po2,
        if real_proof { "real-composite" } else { "fast" }
    );
    println!("This is a diagnostic workload, not a valid SPHINCS+/DAA proof statement.");

    run(0, seg_po2, &backend_hash, real_proof);
    run(1, seg_po2, &backend_hash, real_proof);
}
