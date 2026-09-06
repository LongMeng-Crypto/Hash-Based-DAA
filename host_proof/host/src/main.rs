use std::io::Write;
use std::path::Path;
use std::time::Instant;
use std::{env, fs};

mod issuer_wots;

use methods::{FSPHINCS_GUEST_ELF, FSPHINCS_GUEST_ID, GUEST_ELF, GUEST_ID};
use risc0_zkvm::recursion::identity as recursion_identity;
use risc0_zkvm::{
    default_prover, ExecutorEnv, InnerReceipt, ProverOpts, Receipt, ReceiptKind, VerifierContext,
    DEFAULT_MAX_PO2,
};

#[cfg(not(daa_tpm_sha2))]
use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
#[cfg(all(not(daa_tpm_sha2), lambda_128))]
use aes::Aes128;
#[cfg(all(not(daa_tpm_sha2), lambda_192))]
use aes::Aes192;
#[cfg(all(not(daa_tpm_sha2), lambda_256))]
use aes::Aes256;

#[cfg(daa_tpm_sha2)]
mod daa_sha_hook;

extern "C" {
    fn crypto_sign_keypair(pk: *mut u8, sk: *mut u8) -> i32;
    fn crypto_sign(sm: *mut u8, smlen: *mut u64, m: *const u8, mlen: u64, sk: *const u8) -> i32;
    fn crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> i32;
    fn sphincs_issuer_anchor_certificate_bytes() -> usize;
    fn sphincs_issuer_anchor_generate(
        certificate: *mut u8,
        certificate_len: *mut usize,
        pk: *const u8,
        sk: *const u8,
    ) -> i32;
    fn sphincs_issuer_anchor_verify(
        certificate: *const u8,
        certificate_len: usize,
        pk: *const u8,
    ) -> i32;
    fn sphincs_issuer_anchor_relation(
        seed: *mut u8,
        seeded_state: *mut u8,
        compressed_address: *mut u8,
        anchor_value: *mut u8,
        certificate: *const u8,
        certificate_len: usize,
        pk: *const u8,
        sk: *const u8,
    ) -> i32;
    fn sphincs_sig_bytes() -> usize;
    fn sphincs_pk_bytes() -> usize;
    fn sphincs_sk_bytes() -> usize;
    fn fsphincs_publickeybytes() -> usize;
    fn fsphincs_secretkeybytes() -> usize;
    fn fsphincs_signaturebytes() -> usize;
    fn fsphincs_keypair(pk: *mut u8, sk: *mut u8) -> i32;
    fn fsphincs_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        msg: *const u8,
        msglen: usize,
        sk: *const u8,
    ) -> i32;
    fn fsphincs_verify(
        sig: *const u8,
        siglen: usize,
        msg: *const u8,
        msglen: usize,
        pk: *const u8,
    ) -> i32;
    fn fsphincs_issuer_anchor_certificate_bytes() -> usize;
    fn fsphincs_issuer_anchor_generate(
        certificate: *mut u8,
        certificate_len: usize,
        pk: *const u8,
        sk: *const u8,
    ) -> i32;
    fn fsphincs_issuer_anchor_verify(
        certificate: *const u8,
        certificate_len: usize,
        pk: *const u8,
    ) -> i32;
    fn fsphincs_issuer_anchor_relation(
        master_seed: *mut u8,
        node_address: *mut u8,
        leaf_address: *mut u8,
        anchor_value: *mut u8,
        certificate: *const u8,
        certificate_len: usize,
        pk: *const u8,
        sk: *const u8,
    ) -> i32;
}

const FSPHINCS_N: usize = 32;
const FSPHINCS_D: usize = 16;
#[cfg(fsphincs_k_22)]
const FSPHINCS_K: usize = 22;
#[cfg(fsphincs_k_33)]
const FSPHINCS_K: usize = 33;
#[cfg(fsphincs_k_35)]
const FSPHINCS_K: usize = 35;
#[cfg(fsphincs_k_43)]
const FSPHINCS_K: usize = 43;
#[cfg(fsphincs_k_70)]
const FSPHINCS_K: usize = 70;
const FSPHINCS_LAYER_SIG_BYTES: usize = FSPHINCS_K * (FSPHINCS_D + 1) * FSPHINCS_N;

fn credential_is_fsphincs() -> bool {
    env!("DAA_CREDENTIAL_SCHEME") == "fsphincs"
}

fn credential_pk_bytes() -> usize {
    unsafe {
        if credential_is_fsphincs() {
            fsphincs_publickeybytes()
        } else {
            sphincs_pk_bytes()
        }
    }
}

fn credential_sk_bytes() -> usize {
    unsafe {
        if credential_is_fsphincs() {
            fsphincs_secretkeybytes()
        } else {
            sphincs_sk_bytes()
        }
    }
}

fn credential_sig_bytes() -> usize {
    unsafe {
        if credential_is_fsphincs() {
            fsphincs_signaturebytes()
        } else {
            sphincs_sig_bytes()
        }
    }
}

fn receipt_kind_from_env() -> ReceiptKind {
    match env::var("RISC0_RECEIPT_KIND")
        .unwrap_or_else(|_| "composite".to_string())
        .as_str()
    {
        "composite" => ReceiptKind::Composite,
        "succinct" => ReceiptKind::Succinct,
        other => panic!(
            "unsupported RISC0_RECEIPT_KIND={}; expected composite or succinct",
            other
        ),
    }
}

fn prover_opts_from_env(backend_hash: String) -> ProverOpts {
    let receipt_kind = receipt_kind_from_env();
    let opts = match receipt_kind {
        ReceiptKind::Composite => ProverOpts::composite(),
        ReceiptKind::Succinct => ProverOpts::succinct(),
        _ => panic!("unsupported receipt kind for this benchmark"),
    };
    opts.with_hashfn(backend_hash)
        .with_receipt_kind(receipt_kind)
}

fn verifier_context_for_hashfn(backend_hash: &str, _seg_po2: u32) -> VerifierContext {
    // Succinct and identity receipts commit to the complete default control
    // set, independently of the execution segment limit selected for a run.
    VerifierContext::from_max_po2_with_hashfn_public(backend_hash, DEFAULT_MAX_PO2)
        .expect("unsupported verifier context hash function")
}

fn identity_wrap_enabled() -> bool {
    matches!(
        env::var("RISC0_IDENTITY_WRAP").as_deref(),
        Ok("1") | Ok("true")
    )
}

fn maybe_identity_wrap_receipt(receipt: Receipt) -> Receipt {
    if !identity_wrap_enabled() {
        return receipt;
    }

    match receipt.inner {
        InnerReceipt::Succinct(inner) => {
            println!("identity wrap = enabled");
            let wrapped = recursion_identity(&inner).expect("identity recursion wrap failed");
            Receipt::new(InnerReceipt::Succinct(wrapped), receipt.journal.bytes)
        }
        other => panic!(
            "RISC0_IDENTITY_WRAP requires a succinct receipt, got {:?}",
            other
        ),
    }
}

#[no_mangle]
pub unsafe extern "C" fn randombytes(out: *mut u8, outlen: usize) {
    use rand::RngCore;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use std::sync::{Mutex, OnceLock};

    static RNG: OnceLock<Mutex<ChaCha20Rng>> = OnceLock::new();
    let mut rng = RNG
        .get_or_init(|| Mutex::new(ChaCha20Rng::from_seed([7u8; 32])))
        .lock()
        .unwrap();
    let slice = core::slice::from_raw_parts_mut(out, outlen);
    rng.fill_bytes(slice);
}

// ── AES hook variants ──────────────────────────────────────────────────────
// lambda=128: key=16B, et_u=16B → hk = AES_s(et_u)  (pure ECB, no XOR)
#[cfg(all(not(daa_tpm_sha2), lambda_128))]
fn hook(s: &[u8], et_u: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new(GenericArray::from_slice(s));
    let mut block = GenericArray::clone_from_slice(et_u);
    cipher.encrypt_block(&mut block);
    block.to_vec()
}

// lambda=192: key=24B (AES-192), et_u=32B → hk = AES_s(et_u[0..15]) || AES_s(et_u[16..31])
#[cfg(all(not(daa_tpm_sha2), lambda_192))]
fn hook(s: &[u8], et_u: &[u8]) -> Vec<u8> {
    let cipher = Aes192::new(GenericArray::from_slice(s));
    let mut hk = Vec::with_capacity(32);
    for chunk in 0..2 {
        let off = chunk * 16;
        let mut block = GenericArray::clone_from_slice(&et_u[off..off + 16]);
        cipher.encrypt_block(&mut block);
        hk.extend_from_slice(&block);
    }
    hk
}

// lambda=256: key=32B (AES-256), et_u=32B → hk = AES_s(et_u[0..15]) || AES_s(et_u[16..31])
#[cfg(all(not(daa_tpm_sha2), lambda_256))]
fn hook(s: &[u8], et_u: &[u8]) -> Vec<u8> {
    let cipher = Aes256::new(GenericArray::from_slice(s));
    let mut hk = Vec::with_capacity(32);
    for chunk in 0..2 {
        let off = chunk * 16;
        let mut block = GenericArray::clone_from_slice(&et_u[off..off + 16]);
        cipher.encrypt_block(&mut block);
        hk.extend_from_slice(&block);
    }
    hk
}

#[cfg(all(daa_tpm_sha2, not(daa_tpm_sha_chen23), lambda_128))]
fn hook(s: &[u8], et_u: &[u8]) -> Vec<u8> {
    daa_sha_hook::sha256_hook(s.try_into().unwrap(), et_u.try_into().unwrap()).to_vec()
}

#[cfg(all(daa_tpm_sha2, not(daa_tpm_sha_chen23), lambda_192))]
fn hook(s: &[u8], et_u: &[u8]) -> Vec<u8> {
    daa_sha_hook::sha384_hook(s.try_into().unwrap(), et_u.try_into().unwrap()).to_vec()
}

#[cfg(all(daa_tpm_sha2, not(daa_tpm_sha_chen23), lambda_256))]
fn hook(s: &[u8], et_u: &[u8]) -> Vec<u8> {
    daa_sha_hook::sha512_hook(s.try_into().unwrap(), et_u.try_into().unwrap()).to_vec()
}

#[cfg(all(daa_tpm_sha_chen23, lambda_128))]
fn cdenw23_hooks(sst: &[u8], et_u: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (hk, cet) =
        daa_sha_hook::sha256_cdenw23_hooks(sst.try_into().unwrap(), et_u.try_into().unwrap());
    (hk.to_vec(), cet.to_vec())
}

#[cfg(all(daa_tpm_sha_chen23, lambda_192))]
fn cdenw23_hooks(sst: &[u8], et_u: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (hk, cet) =
        daa_sha_hook::sha384_cdenw23_hooks(sst.try_into().unwrap(), et_u.try_into().unwrap());
    (hk.to_vec(), cet.to_vec())
}

#[cfg(all(daa_tpm_sha_chen23, lambda_256))]
fn cdenw23_hooks(sst: &[u8], et_u: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (hk, cet) =
        daa_sha_hook::sha512_cdenw23_hooks(sst.try_into().unwrap(), et_u.try_into().unwrap());
    (hk.to_vec(), cet.to_vec())
}

// ── Compile-time sizes (bytes) ─────────────────────────────────────────────
// AES retains its historical lengths. SHA mode carries full SHA-2 digests.
#[cfg(all(not(daa_tpm_sha2), lambda_128))]
const ET_BYTES: usize = 16;
#[cfg(all(not(daa_tpm_sha2), any(lambda_192, lambda_256)))]
const ET_BYTES: usize = 32;
#[cfg(all(daa_tpm_sha2, lambda_128))]
const ET_BYTES: usize = 32;
#[cfg(all(daa_tpm_sha2, lambda_192))]
const ET_BYTES: usize = 48;
#[cfg(all(daa_tpm_sha2, lambda_256))]
const ET_BYTES: usize = 64;

#[cfg(all(not(daa_tpm_sha2), lambda_128))]
const NONCE_BYTES: usize = 16;
#[cfg(all(not(daa_tpm_sha2), any(lambda_192, lambda_256)))]
const NONCE_BYTES: usize = 32;
#[cfg(all(daa_tpm_sha2, lambda_128))]
const NONCE_BYTES: usize = 16;
#[cfg(all(daa_tpm_sha2, lambda_192))]
const NONCE_BYTES: usize = 24;
#[cfg(all(daa_tpm_sha2, lambda_256))]
const NONCE_BYTES: usize = 32;

#[cfg(all(not(daa_tpm_sha_chen23), lambda_128))]
const HOOK_SECRET_BYTES: usize = 16;
#[cfg(all(not(daa_tpm_sha_chen23), lambda_192))]
const HOOK_SECRET_BYTES: usize = 24;
#[cfg(all(not(daa_tpm_sha_chen23), lambda_256))]
const HOOK_SECRET_BYTES: usize = 32;
#[cfg(all(daa_tpm_sha_chen23, lambda_128))]
const HOOK_SECRET_BYTES: usize = 32;
#[cfg(all(daa_tpm_sha_chen23, lambda_192))]
const HOOK_SECRET_BYTES: usize = 48;
#[cfg(all(daa_tpm_sha_chen23, lambda_256))]
const HOOK_SECRET_BYTES: usize = 64;
#[cfg(not(daa_tpm_sha_chen23))]
const CET_BYTES: usize = 0;
#[cfg(daa_tpm_sha_chen23)]
const CET_BYTES: usize = ET_BYTES;

/// Dispatches protocol/Setup commands or runs the standalone host benchmark.
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.get(1).map(String::as_str) == Some("prove-protocol")
        || args.get(1).map(String::as_str) == Some("verify-protocol")
        || args.get(1).map(String::as_str) == Some("issuer-keygen")
        || args.get(1).map(String::as_str) == Some("issuer-sign")
        || args.get(1).map(String::as_str) == Some("issuer-verify")
        || args.get(1).map(String::as_str) == Some("issuer-anchor")
        || args.get(1).map(String::as_str) == Some("issuer-anchor-verify")
        || args.get(1).map(String::as_str) == Some("issuer-setup-anchor")
        || args.get(1).map(String::as_str) == Some("issuer-wots-prove")
        || args.get(1).map(String::as_str) == Some("issuer-wots-verify")
    {
        protocol_cli(&args).unwrap();
        return;
    }

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    println!(
        "SPHINCS+ params={} thash={} backend={} N={}B",
        env!("SPHINCS_PARAMS"),
        env!("SPHINCS_THASH"),
        env!("SPHINCS_HASH_BACKEND"),
        env!("SPHINCS_N"),
    );

    // ── 1) SPHINCS+ keygen ────────────────────────────────────────────────
    let pk_bytes = unsafe { sphincs_pk_bytes() };
    let sk_bytes = unsafe { sphincs_sk_bytes() };
    let sig_bytes = unsafe { sphincs_sig_bytes() };
    println!(
        "SPHINCS+ sizes: pk={} B, sk={} B, sig={} B",
        pk_bytes, sk_bytes, sig_bytes
    );

    let mut pk = vec![0u8; pk_bytes];
    let mut sk = vec![0u8; sk_bytes];

    let t_keygen = Instant::now();
    let r = unsafe { crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) };
    let keygen_ms = t_keygen.elapsed().as_micros() as f64 / 1000.0;
    assert_eq!(r, 0);

    // ── 2) Construct message = et_u || gr_u ───────────────────────────────
    // et_u: entry token  (TPM secret, 16 B for lambda=128, 32 B for 192/256)
    // gr_u: issuer-provided nonce (separate from the hook digest length)
    // The DAA host proves: SPHINCS+ sig is valid over et_u || gr_u
    use rand::RngCore;
    use rand_core::SeedableRng;
    let deterministic = std::env::var("DAA_DETERMINISTIC").ok().as_deref() == Some("1");
    let mut deterministic_rng = rand_chacha::ChaCha20Rng::from_seed([11u8; 32]);
    let mut et_u = vec![0u8; ET_BYTES];
    let mut issuer_nonce = vec![0u8; NONCE_BYTES];
    if deterministic {
        deterministic_rng.fill_bytes(&mut et_u);
        deterministic_rng.fill_bytes(&mut issuer_nonce);
    } else {
        rand::thread_rng().fill_bytes(&mut et_u);
        rand::thread_rng().fill_bytes(&mut issuer_nonce);
    }

    // msg fed to SPHINCS+ sign = et_u || gr_u
    // SPHINCS+ internally applies hash_message (acting as H3) to derive mt_u || idx
    let mut msg = Vec::with_capacity(ET_BYTES + NONCE_BYTES);
    msg.extend_from_slice(&et_u);
    msg.extend_from_slice(&issuer_nonce);

    // ── 3) Sign ───────────────────────────────────────────────────────────
    let mut sm_buf = vec![0u8; sig_bytes + msg.len() + 64];
    let mut smlen: u64 = 0;

    let t_sign = Instant::now();
    let r = unsafe {
        crypto_sign(
            sm_buf.as_mut_ptr(),
            &mut smlen as *mut u64,
            msg.as_ptr(),
            msg.len() as u64,
            sk.as_ptr(),
        )
    };
    let sign_ms = t_sign.elapsed().as_micros() as f64 / 1000.0;
    assert_eq!(r, 0);
    sm_buf.truncate(smlen as usize);

    assert!(
        sm_buf.len() >= sig_bytes,
        "signed message shorter than sig_bytes"
    );
    let sig = sm_buf[..sig_bytes].to_vec();
    let msg2 = sm_buf[sig_bytes..].to_vec();
    assert_eq!(msg2, msg, "crypto_sign did not append the same message");

    println!(
        "SPHINCS+ keygen = {:.2} ms, signing = {:.2} ms",
        keygen_ms, sign_ms
    );
    println!(
        "DAA message: et_u={}B || gr_u={}B, hook_backend={} relation={} secret={}B hk={}B",
        ET_BYTES,
        NONCE_BYTES,
        env!("DAA_TPM_BACKEND"),
        env!("DAA_TPM_SHA_SCHEME"),
        HOOK_SECRET_BYTES,
        ET_BYTES,
    );

    // ── 4) TPM hook witnesses ─────────────────────────────────────────────
    // Ours uses s as the secret hook preimage; CDENW'23 uses the hidden sst.
    let mut hook_secret = vec![0u8; HOOK_SECRET_BYTES];
    if deterministic {
        deterministic_rng.fill_bytes(&mut hook_secret);
    } else {
        rand::thread_rng().fill_bytes(&mut hook_secret);
    }

    #[cfg(not(daa_tpm_sha_chen23))]
    let (hk, cet) = (hook(&hook_secret, &et_u), Vec::<u8>::new());
    #[cfg(daa_tpm_sha_chen23)]
    let (hk, cet) = cdenw23_hooks(&hook_secret, &et_u);
    println!(
        "DAA hook public outputs: hk={}B cet={}B",
        hk.len(),
        cet.len()
    );

    // ── 5) Build guest env ────────────────────────────────────────────────
    let seg_po2: u32 = std::env::var("RISC0_SEGMENT_LIMIT_PO2")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(21);

    if seg_po2 > 22 {
        panic!(
            "RISC0_SEGMENT_LIMIT_PO2={} exceeds CUDA-safe maximum 22",
            seg_po2
        );
    }

    // All values are private witnesses fed to the zkVM guest.
    // The guest reconstructs msg = et_u || gr_u internally — et_u is never exposed.
    // Order must match guest env::read() order exactly.
    let mut env_builder = ExecutorEnv::builder();
    env_builder
        .segment_limit_po2(seg_po2)
        .write_slice(&pk)
        .write_slice(&sig)
        .write_slice(&hk);
    #[cfg(daa_tpm_sha_chen23)]
    env_builder.write_slice(&cet);
    env_builder
        .write_slice(&hook_secret)
        .write_slice(&et_u)
        .write_slice(&issuer_nonce);
    let env = env_builder.build().unwrap();

    // ── 6) Prove ──────────────────────────────────────────────────────────
    let prover = default_prover();
    let backend_hash =
        std::env::var("RISC0_BACKEND_HASH").unwrap_or_else(|_| "sha-256".to_string());
    let opts = prover_opts_from_env(backend_hash.clone());

    println!(
        "start proving (seg_po2={}, backend hashfn={})",
        seg_po2, opts.hashfn
    );
    let t0 = Instant::now();
    let prove_info = prover.prove_with_opts(env, GUEST_ELF, &opts).unwrap();
    let stats = prove_info.stats.clone();

    let receipt = maybe_identity_wrap_receipt(prove_info.receipt);
    let prove_elapsed = t0.elapsed();
    print_and_check_segment_hashes(&receipt, &backend_hash);
    let journal = receipt.journal.bytes.as_slice();
    assert_eq!(&journal[..4], &1u32.to_le_bytes());
    assert_eq!(&journal[4..4 + hk.len()], hk.as_slice());
    #[allow(unused_mut)]
    let mut public_end = 4 + hk.len();
    #[cfg(daa_tpm_sha_chen23)]
    {
        assert_eq!(&journal[public_end..public_end + cet.len()], cet.as_slice());
        public_end += cet.len();
    }
    assert_eq!(&journal[public_end..public_end + pk.len()], pk.as_slice());
    #[cfg(not(sphincs_profile))]
    assert_eq!(journal.len(), public_end + pk.len());
    #[cfg(sphincs_profile)]
    print_profile(&journal[public_end + pk.len()..]);

    let proof_bytes =
        risc0_zkvm::serde::to_vec(&receipt).unwrap().len() * core::mem::size_of::<u32>();
    let seal_bytes = receipt.seal_size();
    println!(
        "done proving, prover time = {:.3} ms, proof size = {} bytes",
        prove_elapsed.as_secs_f64() * 1000.0,
        proof_bytes
    );
    println!("prover_us={}", prove_elapsed.as_micros());
    println!("proof_bytes={proof_bytes}");
    println!("seal_bytes={seal_bytes}");
    println!(
        "guest cycles: user={} total={} paging={} reserved={} segments={}",
        stats.user_cycles,
        stats.total_cycles,
        stats.paging_cycles,
        stats.reserved_cycles,
        stats.segments,
    );

    // ── 7) Verify ─────────────────────────────────────────────────────────
    let verifier_ctx = verifier_context_for_hashfn(&backend_hash, seg_po2);
    let t1 = Instant::now();
    receipt
        .verify_with_context(&verifier_ctx, GUEST_ID)
        .unwrap();
    let verify_elapsed = t1.elapsed();
    println!(
        "verify ok, verifier time = {:.3} ms",
        verify_elapsed.as_secs_f64() * 1000.0
    );
    println!("verifier_us={}", verify_elapsed.as_micros());
}

/// Dispatches the existing credential/protocol commands and alternative Setup proof.
fn protocol_cli(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    match args[1].as_str() {
        "prove-protocol" if args.len() == 4 => {
            protocol_prove(Path::new(&args[2]), Path::new(&args[3]))
        }
        "verify-protocol" if args.len() == 4 => {
            protocol_verify(Path::new(&args[2]), Path::new(&args[3]))
        }
        "issuer-keygen" if args.len() == 3 => protocol_issuer_keygen(Path::new(&args[2])),
        "issuer-sign" if args.len() == 4 => {
            protocol_issuer_sign(Path::new(&args[2]), Path::new(&args[3]))
        }
        "issuer-verify" if args.len() == 3 => protocol_issuer_verify(Path::new(&args[2])),
        "issuer-anchor" if args.len() == 4 => {
            protocol_issuer_anchor(Path::new(&args[2]), Path::new(&args[3]))
        }
        "issuer-anchor-verify" if args.len() == 3 => {
            protocol_issuer_anchor_verify(Path::new(&args[2]))
        }
        "issuer-setup-anchor" if args.len() == 3 => {
            protocol_issuer_setup_anchor(Path::new(&args[2]))
        }
        "issuer-wots-prove" if args.len() == 4 => {
            issuer_wots::prove(Path::new(&args[2]), Path::new(&args[3]))
        }
        "issuer-wots-verify" if args.len() == 4 => {
            issuer_wots::verify(Path::new(&args[2]), Path::new(&args[3]))
        }
        _ => unreachable!(),
    }
}

fn protocol_issuer_keygen(output_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let pk_bytes = credential_pk_bytes();
    let sk_bytes = credential_sk_bytes();
    let mut pk = vec![0u8; pk_bytes];
    let mut sk = vec![0u8; sk_bytes];
    let t0 = Instant::now();
    let ret = unsafe {
        if credential_is_fsphincs() {
            fsphincs_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
        } else {
            crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
        }
    };
    if ret != 0 {
        return Err("SPHINCS+ keygen failed".into());
    }
    write_parts(output_path, &[&pk, &sk])?;
    println!("accepted=1");
    println!("keygen_ms={}", t0.elapsed().as_millis());
    println!("pk_bytes={pk_bytes}");
    println!("sk_bytes={sk_bytes}");
    Ok(())
}

fn protocol_issuer_sign(
    input_path: &Path,
    output_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let parts = read_parts(input_path)?;
    if parts.len() != 2 {
        return Err("issuer-sign input must contain sk and message".into());
    }
    let sk = &parts[0];
    let msg = &parts[1];
    let sig_bytes = credential_sig_bytes();
    let t0 = Instant::now();
    let signature = if credential_is_fsphincs() {
        let mut signature = vec![0u8; sig_bytes];
        let mut signature_len = 0usize;
        let ret = unsafe {
            fsphincs_sign_signature(
                signature.as_mut_ptr(),
                &mut signature_len,
                msg.as_ptr(),
                msg.len(),
                sk.as_ptr(),
            )
        };
        if ret != 0 || signature_len != sig_bytes {
            return Err("F-SPHINCS+ signing failed".into());
        }
        signature
    } else {
        let mut signed = vec![0u8; sig_bytes + msg.len() + 64];
        let mut signed_len = 0u64;
        let ret = unsafe {
            crypto_sign(
                signed.as_mut_ptr(),
                &mut signed_len,
                msg.as_ptr(),
                msg.len() as u64,
                sk.as_ptr(),
            )
        };
        if ret != 0 || (signed_len as usize) < sig_bytes {
            return Err("SPHINCS+ signing failed".into());
        }
        signed[..sig_bytes].to_vec()
    };
    write_parts(output_path, &[&signature])?;
    println!("accepted=1");
    println!("sign_ms={}", t0.elapsed().as_millis());
    println!("sig_bytes={sig_bytes}");
    Ok(())
}

fn protocol_issuer_verify(input_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let parts = read_parts(input_path)?;
    if parts.len() != 3 {
        return Err("issuer-verify input must contain pk, message, and signature".into());
    }
    let t0 = Instant::now();
    let ret = unsafe {
        if credential_is_fsphincs() {
            fsphincs_verify(
                parts[2].as_ptr(),
                parts[2].len(),
                parts[1].as_ptr(),
                parts[1].len(),
                parts[0].as_ptr(),
            )
        } else {
            crypto_sign_verify(
                parts[2].as_ptr(),
                parts[2].len(),
                parts[1].as_ptr(),
                parts[1].len(),
                parts[0].as_ptr(),
            )
        }
    };
    println!("accepted={}", if ret == 0 { 1 } else { 0 });
    println!("verifier_ms={}", t0.elapsed().as_millis());
    Ok(())
}

/// Builds native anchor material from an existing issuer keypair.
fn protocol_issuer_anchor(
    input_path: &Path,
    output_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let parts = read_parts(input_path)?;
    if parts.len() != 2 {
        return Err("issuer-anchor input must contain pk and sk".into());
    }
    let pk = &parts[0];
    let sk = &parts[1];
    if pk.len() != credential_pk_bytes() || sk.len() != credential_sk_bytes() {
        return Err("issuer-anchor key length mismatch".into());
    }

    let material = generate_anchor_material(pk, sk)?;
    write_parts(
        output_path,
        &[
            &material.certificate,
            &material.witness,
            &material.public_a,
            &material.public_b,
            &material.anchor_value,
        ],
    )?;
    print_anchor_metrics(&material);
    Ok(())
}

/// Carries the native certificate and exact public/private NIZK relation fields.
struct NativeAnchorMaterial {
    certificate: Vec<u8>,
    witness: Vec<u8>,
    public_a: Vec<u8>,
    public_b: Vec<u8>,
    anchor_value: Vec<u8>,
    generation_us: u128,
    verify_us: u128,
}

/// Generates, verifies, mutation-tests, and exports one scheme-specific anchor.
fn generate_anchor_material(
    pk: &[u8],
    sk: &[u8],
) -> Result<NativeAnchorMaterial, Box<dyn std::error::Error>> {
    if issuer_wots::enabled() {
        return issuer_wots::generate(pk, sk);
    }
    let certificate_bytes = unsafe {
        if credential_is_fsphincs() {
            fsphincs_issuer_anchor_certificate_bytes()
        } else {
            sphincs_issuer_anchor_certificate_bytes()
        }
    };
    let mut certificate = vec![0u8; certificate_bytes];
    let mut actual_certificate_len = certificate.len();
    let generation_started = Instant::now();
    let generated = unsafe {
        if credential_is_fsphincs() {
            fsphincs_issuer_anchor_generate(
                certificate.as_mut_ptr(),
                certificate.len(),
                pk.as_ptr(),
                sk.as_ptr(),
            )
        } else {
            sphincs_issuer_anchor_generate(
                certificate.as_mut_ptr(),
                &mut actual_certificate_len,
                pk.as_ptr(),
                sk.as_ptr(),
            )
        }
    };
    let generation_us = generation_started.elapsed().as_micros();
    if generated != 0 {
        return Err("issuer anchor generation failed".into());
    }
    certificate.truncate(actual_certificate_len);

    let verify_started = Instant::now();
    let verified = unsafe {
        if credential_is_fsphincs() {
            fsphincs_issuer_anchor_verify(certificate.as_ptr(), certificate.len(), pk.as_ptr())
        } else {
            sphincs_issuer_anchor_verify(certificate.as_ptr(), certificate.len(), pk.as_ptr())
        }
    };
    let verify_us = verify_started.elapsed().as_micros();
    if verified != 0 {
        return Err("fresh issuer anchor certificate did not verify".into());
    }
    let mut mutated = certificate.clone();
    let mutation_offset = mutated.len() / 2;
    mutated[mutation_offset] ^= 1;
    let mutation_accepted = unsafe {
        if credential_is_fsphincs() {
            fsphincs_issuer_anchor_verify(mutated.as_ptr(), mutated.len(), pk.as_ptr()) == 0
        } else {
            sphincs_issuer_anchor_verify(mutated.as_ptr(), mutated.len(), pk.as_ptr()) == 0
        }
    };
    if mutation_accepted {
        return Err("mutated issuer anchor certificate was accepted".into());
    }

    let mut witness = vec![
        0u8;
        if credential_is_fsphincs() {
            FSPHINCS_N
        } else {
            env!("SPHINCS_N").parse::<usize>()?
        }
    ];
    let mut public_a = vec![0u8; if credential_is_fsphincs() { 64 } else { 32 }];
    let mut public_b = vec![0u8; if credential_is_fsphincs() { 64 } else { 44 }];
    let mut anchor_value = vec![0u8; 2 * witness.len()];
    let related = unsafe {
        if credential_is_fsphincs() {
            fsphincs_issuer_anchor_relation(
                witness.as_mut_ptr(),
                public_a.as_mut_ptr(),
                public_b.as_mut_ptr(),
                anchor_value.as_mut_ptr(),
                certificate.as_ptr(),
                certificate.len(),
                pk.as_ptr(),
                sk.as_ptr(),
            )
        } else {
            sphincs_issuer_anchor_relation(
                witness.as_mut_ptr(),
                public_a.as_mut_ptr(),
                public_b.as_mut_ptr(),
                anchor_value.as_mut_ptr(),
                certificate.as_ptr(),
                certificate.len(),
                pk.as_ptr(),
                sk.as_ptr(),
            )
        }
    };
    if related != 0 {
        return Err("issuer anchor relation extraction failed".into());
    }

    Ok(NativeAnchorMaterial {
        certificate,
        witness,
        public_a,
        public_b,
        anchor_value,
        generation_us,
        verify_us,
    })
}

/// Emits stable machine-readable native anchor benchmark metrics.
fn print_anchor_metrics(material: &NativeAnchorMaterial) {
    println!("accepted=1");
    println!("anchor_generation_us={}", material.generation_us);
    println!("certificate_verify_us={}", material.verify_us);
    println!("certificate_bytes={}", material.certificate.len());
    println!("certificate_mutation_test=ok");
}

/// Performs issuer key generation and anchor construction as one Setup command.
fn protocol_issuer_setup_anchor(output_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut pk = vec![0u8; credential_pk_bytes()];
    let mut sk = vec![0u8; credential_sk_bytes()];
    let keygen_started = Instant::now();
    let ret = unsafe {
        if credential_is_fsphincs() {
            fsphincs_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
        } else {
            crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
        }
    };
    let keygen_us = keygen_started.elapsed().as_micros();
    if ret != 0 {
        return Err("issuer keygen failed".into());
    }
    let material = generate_anchor_material(&pk, &sk)?;
    write_parts(
        output_path,
        &[
            &pk,
            &sk,
            &material.certificate,
            &material.witness,
            &material.public_a,
            &material.public_b,
            &material.anchor_value,
        ],
    )?;
    println!("keygen_us={keygen_us}");
    println!("pk_bytes={}", pk.len());
    println!("sk_bytes={}", sk.len());
    print_anchor_metrics(&material);
    Ok(())
}

/// Verifies a serialized public anchor certificate without secret material.
fn protocol_issuer_anchor_verify(input_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let parts = read_parts(input_path)?;
    if parts.len() != 2 {
        return Err("issuer-anchor-verify input must contain pk and certificate".into());
    }
    let started = Instant::now();
    if issuer_wots::enabled() {
        issuer_wots::check_certificate(&parts[0], &parts[1])?;
        println!(
            "accepted=1\ncertificate_verify_us={}",
            started.elapsed().as_micros()
        );
        return Ok(());
    }
    let ret = unsafe {
        if credential_is_fsphincs() {
            fsphincs_issuer_anchor_verify(parts[1].as_ptr(), parts[1].len(), parts[0].as_ptr())
        } else {
            sphincs_issuer_anchor_verify(parts[1].as_ptr(), parts[1].len(), parts[0].as_ptr())
        }
    };
    println!("accepted={}", if ret == 0 { 1 } else { 0 });
    println!("certificate_verify_us={}", started.elapsed().as_micros());
    Ok(())
}

struct ProtocolInput {
    issuer_pk: Vec<u8>,
    credential_sig: Vec<u8>,
    hk: Vec<u8>,
    cet: Vec<u8>,
    hook_secret: Vec<u8>,
    et_u: Vec<u8>,
    issuer_nonce: Vec<u8>,
}

fn protocol_prove(
    input_path: &Path,
    receipt_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let input = read_protocol_input(input_path)?;
    validate_protocol_witness(&input)?;

    let seg_po2 = std::env::var("RISC0_SEGMENT_LIMIT_PO2")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(21);

    if seg_po2 > 22 {
        panic!(
            "RISC0_SEGMENT_LIMIT_PO2={} exceeds CUDA-safe maximum 22",
            seg_po2
        );
    }

    let mut env_builder = ExecutorEnv::builder();
    env_builder.segment_limit_po2(seg_po2);
    if credential_is_fsphincs() {
        env_builder
            .write_slice(&input.issuer_pk)
            .write_slice(&input.hk);
        #[cfg(daa_tpm_sha_chen23)]
        env_builder.write_slice(&input.cet);
        env_builder
            .write_slice(&input.hook_secret)
            .write_slice(&input.et_u)
            .write_slice(&input.issuer_nonce)
            .write_slice(&input.credential_sig[..FSPHINCS_N]);
        for layer in input.credential_sig[FSPHINCS_N..].chunks_exact(FSPHINCS_LAYER_SIG_BYTES) {
            env_builder.write_slice(layer);
        }
    } else {
        env_builder
            .write_slice(&input.issuer_pk)
            .write_slice(&input.credential_sig)
            .write_slice(&input.hk);
        #[cfg(daa_tpm_sha_chen23)]
        env_builder.write_slice(&input.cet);
        env_builder
            .write_slice(&input.hook_secret)
            .write_slice(&input.et_u)
            .write_slice(&input.issuer_nonce);
    }
    let env = env_builder.build()?;

    let backend_hash =
        std::env::var("RISC0_BACKEND_HASH").unwrap_or_else(|_| "sha-256".to_string());
    let opts = prover_opts_from_env(backend_hash.clone());
    let t0 = Instant::now();
    let guest_elf = if credential_is_fsphincs() {
        FSPHINCS_GUEST_ELF
    } else {
        GUEST_ELF
    };
    let prove_info = default_prover().prove_with_opts(env, guest_elf, &opts)?;
    let prove_ms = t0.elapsed().as_millis();
    let stats = prove_info.stats.clone();
    let receipt = prove_info.receipt;
    print_and_check_segment_hashes(&receipt, &backend_hash);
    check_protocol_journal(&receipt, &input.issuer_pk, &input.hk, &input.cet)?;
    write_receipt_words(receipt_path, &receipt)?;
    let proof_bytes = risc0_zkvm::serde::to_vec(&receipt)?.len() * core::mem::size_of::<u32>();
    let seal_bytes = receipt.seal_size();
    println!("accepted=1");
    println!("prover_ms={prove_ms}");
    println!("proof_bytes={proof_bytes}");
    println!("seal_bytes={seal_bytes}");
    println!("segments={}", stats.segments);
    Ok(())
}

fn validate_protocol_witness(input: &ProtocolInput) -> Result<(), Box<dyn std::error::Error>> {
    if input.issuer_pk.len() != credential_pk_bytes() {
        return Err("host proof issuer public-key length mismatch".into());
    }
    if input.credential_sig.len() != credential_sig_bytes() {
        return Err("host proof credential-signature length mismatch".into());
    }
    if input.hk.len() != ET_BYTES
        || input.et_u.len() != ET_BYTES
        || input.hook_secret.len() != HOOK_SECRET_BYTES
        || input.issuer_nonce.len() != NONCE_BYTES
        || input.cet.len() != CET_BYTES
    {
        return Err(format!(
            "{}:{} hook length mismatch: expected hk/et/secret/nonce={}/{}/{}/{} bytes, got {}/{}/{}/{}",
            env!("DAA_TPM_BACKEND"),
            env!("DAA_TPM_SHA_SCHEME"),
            ET_BYTES,
            ET_BYTES,
            HOOK_SECRET_BYTES,
            NONCE_BYTES,
            input.hk.len(),
            input.et_u.len(),
            input.hook_secret.len(),
            input.issuer_nonce.len(),
        )
        .into());
    }
    Ok(())
}

fn protocol_verify(
    input_path: &Path,
    receipt_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let input = read_protocol_input(input_path)?;
    let receipt = read_receipt_words(receipt_path)?;
    let seg_po2 = std::env::var("RISC0_SEGMENT_LIMIT_PO2")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(21);

    if seg_po2 > 22 {
        panic!(
            "RISC0_SEGMENT_LIMIT_PO2={} exceeds CUDA-safe maximum 22",
            seg_po2
        );
    }
    let backend_hash =
        std::env::var("RISC0_BACKEND_HASH").unwrap_or_else(|_| "sha-256".to_string());
    let verifier_ctx = verifier_context_for_hashfn(&backend_hash, seg_po2);
    let t0 = Instant::now();
    let guest_id = if credential_is_fsphincs() {
        FSPHINCS_GUEST_ID
    } else {
        GUEST_ID
    };
    receipt.verify_with_context(&verifier_ctx, guest_id)?;
    let verify_ms = t0.elapsed().as_millis();
    check_protocol_journal(&receipt, &input.issuer_pk, &input.hk, &input.cet)?;
    println!("accepted=1");
    println!("verifier_ms={verify_ms}");
    Ok(())
}

fn check_protocol_journal(
    receipt: &Receipt,
    issuer_pk: &[u8],
    hk: &[u8],
    cet: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let journal = receipt.journal.bytes.as_slice();
    let public_hook_len = hk.len() + cet.len();
    if journal.len() < 4 + public_hook_len + issuer_pk.len() {
        return Err("journal is too short".into());
    }
    if &journal[..4] != 1u32.to_le_bytes().as_slice() {
        return Err("journal status is not ok".into());
    }
    if &journal[4..4 + hk.len()] != hk {
        return Err("journal hk mismatch".into());
    }
    #[allow(unused_mut)]
    let mut public_end = 4 + hk.len();
    #[cfg(daa_tpm_sha_chen23)]
    {
        if &journal[public_end..public_end + cet.len()] != cet {
            return Err("journal cet mismatch".into());
        }
        public_end += cet.len();
    }
    if &journal[public_end..public_end + issuer_pk.len()] != issuer_pk {
        return Err("journal issuer pk mismatch".into());
    }
    Ok(())
}

fn read_protocol_input(path: &Path) -> Result<ProtocolInput, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    let mut pos = 0usize;
    let issuer_pk = read_part(&bytes, &mut pos)?;
    let credential_sig = read_part(&bytes, &mut pos)?;
    let hk = read_part(&bytes, &mut pos)?;
    #[cfg(daa_tpm_sha_chen23)]
    let cet = read_part(&bytes, &mut pos)?;
    #[cfg(not(daa_tpm_sha_chen23))]
    let cet = Vec::new();
    let hook_secret = read_part(&bytes, &mut pos)?;
    let et_u = read_part(&bytes, &mut pos)?;
    let issuer_nonce = read_part(&bytes, &mut pos)?;
    if pos != bytes.len() {
        return Err("unexpected trailing protocol input".into());
    }
    Ok(ProtocolInput {
        issuer_pk,
        credential_sig,
        hk,
        cet,
        hook_secret,
        et_u,
        issuer_nonce,
    })
}

fn read_parts(path: &Path) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    let mut pos = 0usize;
    let mut parts = Vec::new();
    while pos < bytes.len() {
        parts.push(read_part(&bytes, &mut pos)?);
    }
    Ok(parts)
}

fn write_parts(path: &Path, parts: &[&[u8]]) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = fs::File::create(path)?;
    for part in parts {
        file.write_all(&(part.len() as u64).to_le_bytes())?;
        file.write_all(part)?;
    }
    Ok(())
}

fn read_part(bytes: &[u8], pos: &mut usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if *pos + 8 > bytes.len() {
        return Err("truncated protocol input length".into());
    }
    let mut len_bytes = [0u8; 8];
    len_bytes.copy_from_slice(&bytes[*pos..*pos + 8]);
    *pos += 8;
    let len = u64::from_le_bytes(len_bytes) as usize;
    if *pos + len > bytes.len() {
        return Err("truncated protocol input payload".into());
    }
    let out = bytes[*pos..*pos + len].to_vec();
    *pos += len;
    Ok(out)
}

fn write_receipt_words(path: &Path, receipt: &Receipt) -> Result<(), Box<dyn std::error::Error>> {
    let words: Vec<u32> = risc0_zkvm::serde::to_vec(receipt)?;
    let mut file = fs::File::create(path)?;
    for word in words {
        file.write_all(&word.to_le_bytes())?;
    }
    Ok(())
}

fn read_receipt_words(path: &Path) -> Result<Receipt, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    if bytes.len() % 4 != 0 {
        return Err("receipt byte length is not word-aligned".into());
    }
    let mut words = Vec::with_capacity(bytes.len() / 4);
    for chunk in bytes.chunks_exact(4) {
        let mut word = [0u8; 4];
        word.copy_from_slice(chunk);
        words.push(u32::from_le_bytes(word));
    }
    Ok(risc0_zkvm::serde::from_slice(&words)?)
}

fn print_and_check_segment_hashes(receipt: &Receipt, expected_hashfn: &str) {
    match &receipt.inner {
        InnerReceipt::Composite(inner) => {
            let mut hashfns = Vec::with_capacity(inner.segments.len());
            for segment in &inner.segments {
                hashfns.push(segment.hashfn.as_str());
                assert_eq!(
                    segment.hashfn, expected_hashfn,
                    "unexpected segment hashfn: got {}, expected {}",
                    segment.hashfn, expected_hashfn
                );
            }
            let first_hashfn = hashfns.first().copied().unwrap_or("<none>");
            println!("receipt kind = composite");
            println!("segment hashfn = {}", first_hashfn);
            println!("segment hashfns = {}", hashfns.join(","));
        }
        InnerReceipt::Succinct(inner) => {
            println!("receipt kind = succinct");
            println!("segment hashfn = <hidden by succinct receipt>");
            println!("segment hashfns = <hidden by succinct receipt>");
            println!("succinct hashfn = {}", inner.hashfn);
            println!("succinct control_id = {}", inner.control_id);
            println!(
                "succinct control_proof_index = {}",
                inner.control_inclusion_proof.index
            );
            println!(
                "succinct control_proof_len = {}",
                inner.control_inclusion_proof.digests.len()
            );
        }
        _ if matches!(env::var("RISC0_DEV_MODE").as_deref(), Ok("1") | Ok("true")) => {
            println!("receipt kind = dev-mode fake receipt");
        }
        _ => {
            panic!("expected composite or succinct receipt");
        }
    }
}

#[cfg(sphincs_profile)]
fn print_profile(bytes: &[u8]) {
    const NAMES: [&str; 16] = [
        "verify",
        "hash_message",
        "fors",
        "wots",
        "compute_root",
        "thash",
        "thash_inblocks",
        "thash_1",
        "thash_2",
        "thash_long",
        "sha256_finalize",
        "sha256_compress_blocks",
        "sha256_syscall_chunks",
        "mgf1_256",
        "seed_state",
        "opt_thash_128s",
    ];

    assert_eq!(bytes.len(), NAMES.len() * 8);
    println!("SPHINCS+ guest profile:");
    for (i, name) in NAMES.iter().enumerate() {
        let off = i * 8;
        let value = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
        println!("  {:>22}: {}", name, value);
    }
}
