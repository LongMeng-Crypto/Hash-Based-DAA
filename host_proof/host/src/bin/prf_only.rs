// DAA FORS sk_i PRF Proof (standalone host binary)
//
// Proves: sk_i = prf_addr(SK.seed, PK.seed, ADRS)  for one FORS leaf
// where ADRS has type = SPX_ADDR_TYPE_FORSPRF (6), all other fields zero.
//
// SK.seed is the private witness; everything else is public.
// The proof uses the RISC0 SHA-256 hardware syscall inside the zkVM guest.
//
// Run with:
//   SPHINCS_PARAMS=sphincs-sha2-128s SPHINCS_THASH=simple cargo run --bin prf_only --release

use std::time::Instant;

use methods::PRF_GUEST_ELF;
use methods::PRF_GUEST_ID;
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts};

extern "C" {
    fn crypto_sign_keypair(pk: *mut u8, sk: *mut u8) -> i32;
    fn sphincs_prf_one(out: *mut u8, pk_seed: *const u8, sk_seed: *const u8, adrs_bytes: *const u8);
    fn sphincs_pk_bytes() -> usize;
    fn sphincs_sk_bytes() -> usize;
}

#[no_mangle]
pub unsafe extern "C" fn randombytes(out: *mut u8, outlen: usize) {
    use rand::RngCore;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use std::sync::{Mutex, OnceLock};
    static RNG: OnceLock<Mutex<ChaCha20Rng>> = OnceLock::new();
    let mut rng = RNG
        .get_or_init(|| Mutex::new(ChaCha20Rng::from_seed([9u8; 32])))
        .lock()
        .unwrap();
    let slice = core::slice::from_raw_parts_mut(out, outlen);
    rng.fill_bytes(slice);
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PrfOutputs {
    ok: bool,
    sk_i: Vec<u8>,
}

// SPX_N at compile time (bytes)
#[cfg(lambda_128)]
const SPX_N: usize = 16;
#[cfg(lambda_192)]
const SPX_N: usize = 24;
#[cfg(lambda_256)]
const SPX_N: usize = 32;

// SPX_ADDR_TYPE_FORSPRF = 6 sits at byte offset 9 of the 32-byte ADRS
// (SHA-2 backend, see sha2_offsets.h: OFFSET_TYPE = 9)
fn fors_prf_adrs() -> [u8; 32] {
    let mut adrs = [0u8; 32];
    adrs[9] = 6; // SPX_ADDR_TYPE_FORSPRF
    adrs
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    println!(
        "DAA FORS PRF Proof — params={} thash={} backend={} N={}B",
        env!("SPHINCS_PARAMS"),
        env!("SPHINCS_THASH"),
        env!("SPHINCS_HASH_BACKEND"),
        env!("SPHINCS_N"),
    );

    // ── 1) Generate SPHINCS+ keypair ─────────────────────────────────────
    let pk_bytes = unsafe { sphincs_pk_bytes() };
    let sk_bytes = unsafe { sphincs_sk_bytes() };
    let mut pk = vec![0u8; pk_bytes];
    let mut sk = vec![0u8; sk_bytes];

    let t_kg = Instant::now();
    assert_eq!(
        unsafe { crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) },
        0
    );
    let keygen_ms = t_kg.elapsed().as_micros() as f64 / 1000.0;
    println!("keygen = {:.2} ms", keygen_ms);

    // sk layout: [SK.seed (n) | SK.prf (n) | PK.seed (n) | PK.root (n)]
    // pk layout: [PK.seed (n) | PK.root (n)]
    let sk_seed = sk[..SPX_N].to_vec();
    let pk_seed = pk[..SPX_N].to_vec(); // == sk[2*SPX_N..3*SPX_N]

    // ── 2) Compute the expected PRF output on the host ────────────────────
    let adrs = fors_prf_adrs();
    let mut sk_i = vec![0u8; SPX_N];
    unsafe {
        sphincs_prf_one(
            sk_i.as_mut_ptr(),
            pk_seed.as_ptr(),
            sk_seed.as_ptr(),
            adrs.as_ptr(),
        );
    }
    println!(
        "PRF inputs: pk_seed={}B  sk_seed={}B(secret)  adrs=32B  output={}B",
        SPX_N, SPX_N, SPX_N
    );

    // ── 3) Build guest env ────────────────────────────────────────────────
    // Write order must match prf_guest.rs read order:
    //   pk_seed (public), adrs (public), sk_i (public), sk_seed (private)
    let seg_po2: u32 = std::env::var("RISC0_SEGMENT_LIMIT_PO2")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(21);

    let env = ExecutorEnv::builder()
        .segment_limit_po2(seg_po2)
        .write(&pk_seed)
        .unwrap()
        .write(&adrs.to_vec())
        .unwrap()
        .write(&sk_i)
        .unwrap()
        .write(&sk_seed)
        .unwrap()
        .build()
        .unwrap();

    // ── 4) Prove ──────────────────────────────────────────────────────────
    let prover = default_prover();
    let opts = ProverOpts::fast();
    println!(
        "start PRF proving (seg_po2={}, hashfn={})",
        seg_po2, opts.hashfn
    );

    let t0 = Instant::now();
    let prove_info = prover.prove_with_opts(env, PRF_GUEST_ELF, &opts).unwrap();
    let prove_ms = t0.elapsed().as_millis();
    let stats = prove_info.stats.clone();

    let receipt = prove_info.receipt;
    let out: PrfOutputs = receipt.journal.decode().unwrap();
    assert!(out.ok);
    assert_eq!(out.sk_i, sk_i);

    let proof_bytes =
        risc0_zkvm::serde::to_vec(&receipt).unwrap().len() * core::mem::size_of::<u32>();
    println!(
        "done proving, prf prover time = {} ms, prf proof size = {} bytes",
        prove_ms, proof_bytes
    );
    println!(
        "guest cycles: user={} total={} paging={} reserved={} segments={}",
        stats.user_cycles,
        stats.total_cycles,
        stats.paging_cycles,
        stats.reserved_cycles,
        stats.segments,
    );

    // ── 5) Verify ─────────────────────────────────────────────────────────
    let t1 = Instant::now();
    receipt.verify(PRF_GUEST_ID).unwrap();
    let verify_ms = t1.elapsed().as_millis();
    println!("verify ok, prf verifier time = {} ms", verify_ms);
}
