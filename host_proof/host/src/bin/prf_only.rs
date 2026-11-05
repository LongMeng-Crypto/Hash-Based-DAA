

use std::time::Instant;

use methods::PRF_GUEST_ELF;
use methods::PRF_GUEST_ID;
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts};

extern "C" {

    // Implements crypto sign keypair.
    fn crypto_sign_keypair(pk: *mut u8, sk: *mut u8) -> i32;

    // Implements prf one.
    fn sphincs_prf_one(out: *mut u8, pk_seed: *const u8, sk_seed: *const u8, adrs_bytes: *const u8);

    // Implements pk bytes.
    fn sphincs_pk_bytes() -> usize;

    // Implements sk bytes.
    fn sphincs_sk_bytes() -> usize;
}

#[no_mangle]

// Implements randombytes.
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

#[cfg(lambda_128)]
const SPX_N: usize = 16;
#[cfg(lambda_192)]
const SPX_N: usize = 24;
#[cfg(lambda_256)]
const SPX_N: usize = 32;

// Implements fors prf adrs.
fn fors_prf_adrs() -> [u8; 32] {
    let mut adrs = [0u8; 32];
    adrs[9] = 6;
    adrs
}

// Implements main.
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

    let sk_seed = sk[..SPX_N].to_vec();
    let pk_seed = pk[..SPX_N].to_vec();

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

    let t1 = Instant::now();
    receipt.verify(PRF_GUEST_ID).unwrap();
    let verify_ms = t1.elapsed().as_millis();
    println!("verify ok, prf verifier time = {} ms", verify_ms);
}
