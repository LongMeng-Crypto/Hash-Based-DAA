use std::time::Instant;

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
#[cfg(not(fsphincs_256))]
use aes::Aes128;
#[cfg(fsphincs_256)]
use aes::Aes256;
use methods::{FSPHINCS_GUEST_ELF, FSPHINCS_GUEST_ID};
use risc0_zkvm::{
    default_prover, ExecutorEnv, InnerReceipt, ProverOpts, ReceiptKind, VerifierContext,
};

#[cfg(not(fsphincs_256))]
const K: usize = 35;
#[cfg(fsphincs_256)]
const K: usize = 70;
const N: usize = 32;
const D: usize = 16;
const H: usize = 6;
const MFORS_MSG_BYTES: usize = K * D / 8;
const MFORS_SIG_BYTES: usize = K * (D + 1) * N;
const PK_BYTES: usize = N + MFORS_MSG_BYTES;
const SK_BYTES: usize = 2 * N + MFORS_MSG_BYTES;
const SIG_BYTES: usize = N + (H + 1) * MFORS_SIG_BYTES;
#[cfg(fsphincs_256)]
const ET_GR_BYTES: usize = 32;
#[cfg(not(fsphincs_256))]
const ET_GR_BYTES: usize = 16;
const S_BYTES: usize = ET_GR_BYTES;
const HK_BYTES: usize = ET_GR_BYTES;
const MSG_BYTES: usize = 2 * ET_GR_BYTES;

extern "C" {
    fn fsphincs_keypair(pk: *mut u8, sk: *mut u8) -> i32;
    fn fsphincs_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        msg: *const u8,
        msglen: usize,
        sk: *const u8,
    ) -> i32;
}

#[no_mangle]
pub unsafe extern "C" fn randombytes(out: *mut u8, outlen: usize) {
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use std::sync::{Mutex, OnceLock};
    static RNG: OnceLock<Mutex<ChaCha20Rng>> = OnceLock::new();
    let mut rng = RNG
        .get_or_init(|| Mutex::new(ChaCha20Rng::from_seed([0x52; 32])))
        .lock()
        .unwrap();
    rng.fill_bytes(core::slice::from_raw_parts_mut(out, outlen));
}

fn receipt_kind() -> ReceiptKind {
    match std::env::var("RISC0_RECEIPT_KIND")
        .unwrap_or_else(|_| "composite".to_owned())
        .as_str()
    {
        "composite" => ReceiptKind::Composite,
        "succinct" => ReceiptKind::Succinct,
        other => panic!("unsupported RISC0_RECEIPT_KIND={other}"),
    }
}

#[cfg(not(fsphincs_256))]
fn aes_hook(s: &[u8; S_BYTES], et_u: &[u8; ET_GR_BYTES]) -> [u8; HK_BYTES] {
    let cipher = Aes128::new(GenericArray::from_slice(s));
    let mut block = GenericArray::clone_from_slice(et_u);
    cipher.encrypt_block(&mut block);
    let mut hk = [0u8; HK_BYTES];
    hk.copy_from_slice(&block);
    hk
}

#[cfg(fsphincs_256)]
fn aes_hook(s: &[u8; S_BYTES], et_u: &[u8; ET_GR_BYTES]) -> [u8; HK_BYTES] {
    let cipher = Aes256::new(GenericArray::from_slice(s));
    let mut hk = [0u8; HK_BYTES];
    for chunk in 0..2 {
        let off = chunk * 16;
        let mut block = GenericArray::clone_from_slice(&et_u[off..off + 16]);
        cipher.encrypt_block(&mut block);
        hk[off..off + 16].copy_from_slice(&block);
    }
    hk
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let seg_po2: u32 = std::env::var("RISC0_SEGMENT_LIMIT_PO2")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(22);
    assert!(seg_po2 <= 22, "CUDA-safe maximum segment po2 is 22");
    let backend =
        std::env::var("RISC0_BACKEND_HASH").unwrap_or_else(|_| "sha-256".to_owned());
    let kind = receipt_kind();

    let mut pk = [0u8; PK_BYTES];
    let mut sk = [0u8; SK_BYTES];
    let mut sig = vec![0u8; SIG_BYTES];
    let mut et_u = [0u8; ET_GR_BYTES];
    let mut issuer_nonce = [0u8; ET_GR_BYTES];
    let mut s = [0u8; S_BYTES];
    let mut message = [0u8; MSG_BYTES];
    use rand::RngCore;
    use rand_core::SeedableRng;
    let deterministic = std::env::var("DAA_DETERMINISTIC").ok().as_deref() == Some("1");
    let mut deterministic_rng = rand_chacha::ChaCha20Rng::from_seed([11u8; 32]);
    if deterministic {
        deterministic_rng.fill_bytes(&mut et_u);
        deterministic_rng.fill_bytes(&mut issuer_nonce);
        deterministic_rng.fill_bytes(&mut s);
    } else {
        rand::thread_rng().fill_bytes(&mut et_u);
        rand::thread_rng().fill_bytes(&mut issuer_nonce);
        rand::thread_rng().fill_bytes(&mut s);
    }
    message[..ET_GR_BYTES].copy_from_slice(&et_u);
    message[ET_GR_BYTES..].copy_from_slice(&issuer_nonce);

    let keygen_start = Instant::now();
    assert_eq!(unsafe { fsphincs_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) }, 0);
    let keygen_ms = keygen_start.elapsed().as_secs_f64() * 1000.0;
    let mut siglen = 0usize;
    let sign_start = Instant::now();
    assert_eq!(
        unsafe {
            fsphincs_sign_signature(
                sig.as_mut_ptr(),
                &mut siglen,
                message.as_ptr(),
                message.len(),
                sk.as_ptr(),
            )
        },
        0
    );
    let sign_ms = sign_start.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(siglen, SIG_BYTES);

    let hk = aes_hook(&s, &et_u);

    /* Stream the randomizer and seven M-FORS layers in verifier consumption
     * order. The guest retains only one layer instead of the whole signature. */
    let mut env_builder = ExecutorEnv::builder();
    env_builder
        .segment_limit_po2(seg_po2)
        .write_slice(&pk)
        .write_slice(&hk)
        .write_slice(&s)
        .write_slice(&et_u)
        .write_slice(&issuer_nonce)
        .write_slice(&sig[..N]);
    for layer_sig in sig[N..].chunks_exact(MFORS_SIG_BYTES) {
        env_builder.write_slice(layer_sig);
    }
    let env = env_builder.build().unwrap();

    let base_opts = match kind {
        ReceiptKind::Composite => ProverOpts::composite(),
        ReceiptKind::Succinct => ProverOpts::succinct(),
        _ => unreachable!(),
    };
    let opts = base_opts
        .with_hashfn(backend.clone())
        .with_receipt_kind(kind);
    println!(
        "F-SPHINCS+-{} RISC0 GPU benchmark: backend={} receipt_kind={:?} segment_po2={}",
        env!("FSPHINCS_SECURITY"), backend, kind, seg_po2
    );
    println!(
        "credential: pk={} B sk={} B signature={} B message={} B",
        PK_BYTES, SK_BYTES, SIG_BYTES, MSG_BYTES
    );
    println!(
        "DAA hook: et_u={} B gr_u={} B s={} B hk={} B",
        ET_GR_BYTES, ET_GR_BYTES, S_BYTES, HK_BYTES
    );
    println!("native keygen_ms={keygen_ms:.3} sign_ms={sign_ms:.3}");

    let prove_start = Instant::now();
    let prove_info = default_prover()
        .prove_with_opts(env, FSPHINCS_GUEST_ELF, &opts)
        .expect("F-SPHINCS+ RISC0 proving failed");
    let prover_ms = prove_start.elapsed().as_millis();
    let stats = prove_info.stats.clone();
    let receipt = prove_info.receipt;

    let verifier_context =
        VerifierContext::from_max_po2_with_hashfn_public(&backend, seg_po2 as usize)
            .expect("unsupported verifier context");
    let verify_start = Instant::now();
    receipt
        .verify_with_context(&verifier_context, FSPHINCS_GUEST_ID)
        .expect("F-SPHINCS+ receipt verification failed");
    let verifier_ms = verify_start.elapsed().as_millis();

    let journal = receipt.journal.bytes.as_slice();
    assert_eq!(journal.len(), 4 + HK_BYTES + PK_BYTES);
    assert_eq!(&journal[..4], 1u32.to_le_bytes().as_slice());
    assert_eq!(&journal[4..4 + HK_BYTES], &hk);
    assert_eq!(&journal[4 + HK_BYTES..], &pk);

    let proof_bytes =
        risc0_zkvm::serde::to_vec(&receipt).unwrap().len() * core::mem::size_of::<u32>();
    let seal_bytes = receipt.seal_size();
    match &receipt.inner {
        InnerReceipt::Composite(inner) => {
            let hashes: Vec<_> = inner.segments.iter().map(|s| s.hashfn.as_str()).collect();
            println!("receipt=Composite segment_hashes={}", hashes.join(","));
        }
        InnerReceipt::Succinct(inner) => {
            println!("receipt=Succinct succinct_hashfn={}", inner.hashfn);
        }
        other => println!("receipt={other:?}"),
    }
    println!("prover_ms={prover_ms}");
    println!("verifier_ms={verifier_ms}");
    println!("proof_bytes={proof_bytes}");
    println!("seal_bytes={seal_bytes}");
    println!(
        "guest_cycles: user={} total={} paging={} reserved={} segments={}",
        stats.user_cycles,
        stats.total_cycles,
        stats.paging_cycles,
        stats.reserved_cycles,
        stats.segments
    );
}
