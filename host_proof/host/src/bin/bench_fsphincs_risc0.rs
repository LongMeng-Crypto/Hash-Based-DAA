use std::time::Instant;

#[cfg(not(daa_tpm_sha2))]
use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
#[cfg(all(not(daa_tpm_sha2), not(any(fsphincs_192, fsphincs_256))))]
use aes::Aes128;
#[cfg(all(not(daa_tpm_sha2), fsphincs_192))]
use aes::Aes192;
#[cfg(all(not(daa_tpm_sha2), fsphincs_256))]
use aes::Aes256;
#[cfg(daa_tpm_sha2)]
#[path = "../daa_sha_hook.rs"]
mod daa_sha_hook;
use methods::{FSPHINCS_GUEST_ELF, FSPHINCS_GUEST_ID};
use risc0_zkvm::{
    default_prover, ExecutorEnv, InnerReceipt, ProverOpts, ReceiptKind, VerifierContext,
    DEFAULT_MAX_PO2,
};

#[allow(dead_code)]
mod fs_params {
    include!(concat!(env!("OUT_DIR"), "/fsphincs_params.rs"));
}
const K: usize = fs_params::K;
const N: usize = 32;
const D: usize = fs_params::D;
const H: usize = 6;
const MFORS_MSG_BYTES: usize = (K * D + 7) / 8;
const MFORS_SIG_BYTES: usize = K * (D + 1) * N;
const PK_BYTES: usize = N + MFORS_MSG_BYTES;
const SK_BYTES: usize = 2 * N + MFORS_MSG_BYTES;
const SIG_BYTES: usize = N + (H + 1) * MFORS_SIG_BYTES;
#[cfg(all(not(daa_tpm_sha2), not(any(fsphincs_192, fsphincs_256))))]
const ET_BYTES: usize = 16;
#[cfg(all(not(daa_tpm_sha2), any(fsphincs_192, fsphincs_256)))]
const ET_BYTES: usize = 32;
#[cfg(all(daa_tpm_sha2, not(any(fsphincs_192, fsphincs_256))))]
const ET_BYTES: usize = 32;
#[cfg(all(daa_tpm_sha2, fsphincs_192))]
const ET_BYTES: usize = 48;
#[cfg(all(daa_tpm_sha2, fsphincs_256))]
const ET_BYTES: usize = 64;

#[cfg(all(not(daa_tpm_sha2), not(any(fsphincs_192, fsphincs_256))))]
const NONCE_BYTES: usize = 16;
#[cfg(all(not(daa_tpm_sha2), any(fsphincs_192, fsphincs_256)))]
const NONCE_BYTES: usize = 32;
#[cfg(all(daa_tpm_sha2, not(any(fsphincs_192, fsphincs_256))))]
const NONCE_BYTES: usize = 16;
#[cfg(all(daa_tpm_sha2, fsphincs_192))]
const NONCE_BYTES: usize = 24;
#[cfg(all(daa_tpm_sha2, fsphincs_256))]
const NONCE_BYTES: usize = 32;
#[cfg(all(not(daa_tpm_sha_chen23), not(any(fsphincs_192, fsphincs_256))))]
const HOOK_SECRET_BYTES: usize = 16;
#[cfg(all(not(daa_tpm_sha_chen23), fsphincs_192))]
const HOOK_SECRET_BYTES: usize = 24;
#[cfg(all(not(daa_tpm_sha_chen23), fsphincs_256))]
const HOOK_SECRET_BYTES: usize = 32;
#[cfg(all(daa_tpm_sha_chen23, not(any(fsphincs_192, fsphincs_256))))]
const HOOK_SECRET_BYTES: usize = 32;
#[cfg(all(daa_tpm_sha_chen23, fsphincs_192))]
const HOOK_SECRET_BYTES: usize = 48;
#[cfg(all(daa_tpm_sha_chen23, fsphincs_256))]
const HOOK_SECRET_BYTES: usize = 64;
const HK_BYTES: usize = ET_BYTES;
const MSG_BYTES: usize = ET_BYTES + NONCE_BYTES;

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

#[cfg(all(not(daa_tpm_sha2), not(any(fsphincs_192, fsphincs_256))))]
fn hook(s: &[u8; HOOK_SECRET_BYTES], et_u: &[u8; ET_BYTES]) -> [u8; HK_BYTES] {
    let cipher = Aes128::new(GenericArray::from_slice(s));
    let mut block = GenericArray::clone_from_slice(et_u);
    cipher.encrypt_block(&mut block);
    let mut hk = [0u8; HK_BYTES];
    hk.copy_from_slice(&block);
    hk
}

#[cfg(all(not(daa_tpm_sha2), fsphincs_192))]
fn hook(s: &[u8; HOOK_SECRET_BYTES], et_u: &[u8; ET_BYTES]) -> [u8; HK_BYTES] {
    let cipher = Aes192::new(GenericArray::from_slice(s));
    let mut hk = [0u8; HK_BYTES];
    for chunk in 0..2 {
        let off = chunk * 16;
        let mut block = GenericArray::clone_from_slice(&et_u[off..off + 16]);
        cipher.encrypt_block(&mut block);
        hk[off..off + 16].copy_from_slice(&block);
    }
    hk
}

#[cfg(all(not(daa_tpm_sha2), fsphincs_256))]
fn hook(s: &[u8; HOOK_SECRET_BYTES], et_u: &[u8; ET_BYTES]) -> [u8; HK_BYTES] {
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

#[cfg(all(
    daa_tpm_sha2,
    not(daa_tpm_sha_chen23),
    not(any(fsphincs_192, fsphincs_256))
))]
fn hook(s: &[u8; HOOK_SECRET_BYTES], et_u: &[u8; ET_BYTES]) -> [u8; HK_BYTES] {
    daa_sha_hook::sha256_hook(s, et_u)
}

#[cfg(all(daa_tpm_sha2, not(daa_tpm_sha_chen23), fsphincs_192))]
fn hook(s: &[u8; HOOK_SECRET_BYTES], et_u: &[u8; ET_BYTES]) -> [u8; HK_BYTES] {
    daa_sha_hook::sha384_hook(s, et_u)
}

#[cfg(all(daa_tpm_sha2, not(daa_tpm_sha_chen23), fsphincs_256))]
fn hook(s: &[u8; HOOK_SECRET_BYTES], et_u: &[u8; ET_BYTES]) -> [u8; HK_BYTES] {
    daa_sha_hook::sha512_hook(s, et_u)
}

#[cfg(all(daa_tpm_sha_chen23, not(any(fsphincs_192, fsphincs_256))))]
fn cdenw23_hooks(
    sst: &[u8; HOOK_SECRET_BYTES],
    et_u: &[u8; ET_BYTES],
) -> ([u8; HK_BYTES], [u8; HK_BYTES]) {
    daa_sha_hook::sha256_cdenw23_hooks(sst, et_u)
}

#[cfg(all(daa_tpm_sha_chen23, fsphincs_192))]
fn cdenw23_hooks(
    sst: &[u8; HOOK_SECRET_BYTES],
    et_u: &[u8; ET_BYTES],
) -> ([u8; HK_BYTES], [u8; HK_BYTES]) {
    daa_sha_hook::sha384_cdenw23_hooks(sst, et_u)
}

#[cfg(all(daa_tpm_sha_chen23, fsphincs_256))]
fn cdenw23_hooks(
    sst: &[u8; HOOK_SECRET_BYTES],
    et_u: &[u8; ET_BYTES],
) -> ([u8; HK_BYTES], [u8; HK_BYTES]) {
    daa_sha_hook::sha512_cdenw23_hooks(sst, et_u)
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
    let backend = std::env::var("RISC0_BACKEND_HASH").unwrap_or_else(|_| "sha-256".to_owned());
    let kind = receipt_kind();

    let mut pk = [0u8; PK_BYTES];
    let mut sk = [0u8; SK_BYTES];
    let mut sig = vec![0u8; SIG_BYTES];
    let mut et_u = [0u8; ET_BYTES];
    let mut issuer_nonce = [0u8; NONCE_BYTES];
    let mut hook_secret = [0u8; HOOK_SECRET_BYTES];
    let mut message = [0u8; MSG_BYTES];
    use rand::RngCore;
    use rand_core::SeedableRng;
    let deterministic = std::env::var("DAA_DETERMINISTIC").ok().as_deref() == Some("1");
    let mut deterministic_rng = rand_chacha::ChaCha20Rng::from_seed([11u8; 32]);
    if deterministic {
        deterministic_rng.fill_bytes(&mut et_u);
        deterministic_rng.fill_bytes(&mut issuer_nonce);
        deterministic_rng.fill_bytes(&mut hook_secret);
    } else {
        rand::thread_rng().fill_bytes(&mut et_u);
        rand::thread_rng().fill_bytes(&mut issuer_nonce);
        rand::thread_rng().fill_bytes(&mut hook_secret);
    }
    message[..ET_BYTES].copy_from_slice(&et_u);
    message[ET_BYTES..].copy_from_slice(&issuer_nonce);

    let keygen_start = Instant::now();
    assert_eq!(
        unsafe { fsphincs_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) },
        0
    );
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

    #[cfg(not(daa_tpm_sha_chen23))]
    let (hk, cet): ([u8; HK_BYTES], Option<[u8; HK_BYTES]>) = (hook(&hook_secret, &et_u), None);
    #[cfg(daa_tpm_sha_chen23)]
    let (hk, cet) = {
        let (hk, cet) = cdenw23_hooks(&hook_secret, &et_u);
        (hk, Some(cet))
    };

    /* Stream the randomizer and seven M-FORS layers in verifier consumption
     * order. The guest retains only one layer instead of the whole signature. */
    let mut env_builder = ExecutorEnv::builder();
    env_builder
        .segment_limit_po2(seg_po2)
        .write_slice(&pk)
        .write_slice(&hk);
    #[cfg(daa_tpm_sha_chen23)]
    env_builder.write_slice(cet.as_ref().unwrap());
    env_builder
        .write_slice(&hook_secret)
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
        "F-SPHINCS+-{} format=3 (k={}) RISC0 GPU benchmark: backend={} receipt_kind={:?} segment_po2={}",
        env!("FSPHINCS_PARAMS"),
        env!("FSPHINCS_K"),
        backend,
        kind,
        seg_po2
    );
    println!(
        "credential: pk={} B sk={} B signature={} B message={} B",
        PK_BYTES, SK_BYTES, SIG_BYTES, MSG_BYTES
    );
    println!(
        "DAA hook: backend={} relation={} et_u={} B gr_u={} B secret={} B hk={} B cet={} B",
        env!("DAA_TPM_BACKEND"),
        env!("DAA_TPM_SHA_SCHEME"),
        ET_BYTES,
        NONCE_BYTES,
        HOOK_SECRET_BYTES,
        HK_BYTES,
        cet.as_ref().map_or(0, |value| value.len())
    );
    println!("native keygen_ms={keygen_ms:.3} sign_ms={sign_ms:.3}");

    if std::env::var("FSPHINCS_EXECUTE_ONLY").as_deref() == Ok("1") {
        let session = risc0_zkvm::default_executor()
            .execute(env, FSPHINCS_GUEST_ELF)
            .expect("F-SPHINCS+ guest execution failed");
        let mut expected = 1u32.to_le_bytes().to_vec();
        expected.extend_from_slice(&hk);
        if let Some(cet) = &cet {
            expected.extend_from_slice(cet);
        }
        expected.extend_from_slice(&pk);
        assert_eq!(session.journal.bytes, expected);
        println!(
            "guest_execute=ok parameter={} hook={} format=3",
            env!("FSPHINCS_PARAMS"),
            env!("DAA_TPM_SHA_SCHEME")
        );
        return;
    }

    let prove_start = Instant::now();
    let prove_info = default_prover()
        .prove_with_opts(env, FSPHINCS_GUEST_ELF, &opts)
        .expect("F-SPHINCS+ RISC0 proving failed");
    let prove_elapsed = prove_start.elapsed();
    let stats = prove_info.stats.clone();
    let receipt = prove_info.receipt;

    let verifier_context =
        VerifierContext::from_max_po2_with_hashfn_public(&backend, DEFAULT_MAX_PO2)
            .expect("unsupported verifier context");
    let verify_start = Instant::now();
    receipt
        .verify_with_context(&verifier_context, FSPHINCS_GUEST_ID)
        .expect("F-SPHINCS+ receipt verification failed");
    let verify_elapsed = verify_start.elapsed();

    let journal = receipt.journal.bytes.as_slice();
    let public_hook_bytes = HK_BYTES + cet.as_ref().map_or(0, |value| value.len());
    assert_eq!(journal.len(), 4 + public_hook_bytes + PK_BYTES);
    assert_eq!(&journal[..4], 1u32.to_le_bytes().as_slice());
    assert_eq!(&journal[4..4 + HK_BYTES], &hk);
    let mut public_end = 4 + HK_BYTES;
    if let Some(cet) = &cet {
        assert_eq!(&journal[public_end..public_end + cet.len()], cet);
        public_end += cet.len();
    }
    assert_eq!(&journal[public_end..], &pk);

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
    println!("prover_ms={:.3}", prove_elapsed.as_secs_f64() * 1000.0);
    println!("prover_us={}", prove_elapsed.as_micros());
    println!("verifier_ms={:.3}", verify_elapsed.as_secs_f64() * 1000.0);
    println!("verifier_us={}", verify_elapsed.as_micros());
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
