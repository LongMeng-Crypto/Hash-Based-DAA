use std::io::Write;
use std::path::Path;
use std::time::Instant;
use std::{env, fs};

use methods::{GUEST_ELF, GUEST_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, InnerReceipt, ProverOpts, Receipt, ReceiptKind};

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
#[cfg(lambda_128)]
use aes::Aes128;
#[cfg(lambda_192)]
use aes::Aes192;
#[cfg(lambda_256)]
use aes::Aes256;

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
    fn sphincs_sig_bytes() -> usize;
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
        .get_or_init(|| Mutex::new(ChaCha20Rng::from_seed([7u8; 32])))
        .lock()
        .unwrap();
    let slice = core::slice::from_raw_parts_mut(out, outlen);
    rng.fill_bytes(slice);
}

// ── AES hook variants ──────────────────────────────────────────────────────
// lambda=128: key=16B, et_u=16B → hk = AES_s(et_u)  (pure ECB, no XOR)
#[cfg(lambda_128)]
fn aes_hook(s: &[u8], et_u: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new(GenericArray::from_slice(s));
    let mut block = GenericArray::clone_from_slice(et_u);
    cipher.encrypt_block(&mut block);
    block.to_vec()
}

// lambda=192: key=24B (AES-192), et_u=32B → hk = AES_s(et_u[0..15]) || AES_s(et_u[16..31])
#[cfg(lambda_192)]
fn aes_hook(s: &[u8], et_u: &[u8]) -> Vec<u8> {
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
#[cfg(lambda_256)]
fn aes_hook(s: &[u8], et_u: &[u8]) -> Vec<u8> {
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

// ── Compile-time sizes (bytes) ─────────────────────────────────────────────
// et_u / gr_u:  16 B for lambda=128,  32 B for lambda=192/256
// s (AES key):  16 B / 24 B / 32 B
#[cfg(lambda_128)]
const ET_GR_BYTES: usize = 16;
#[cfg(any(lambda_192, lambda_256))]
const ET_GR_BYTES: usize = 32;

#[cfg(lambda_128)]
const S_BYTES: usize = 16;
#[cfg(lambda_192)]
const S_BYTES: usize = 24;
#[cfg(lambda_256)]
const S_BYTES: usize = 32;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.get(1).map(String::as_str) == Some("prove-protocol")
        || args.get(1).map(String::as_str) == Some("verify-protocol")
        || args.get(1).map(String::as_str) == Some("issuer-keygen")
        || args.get(1).map(String::as_str) == Some("issuer-sign")
        || args.get(1).map(String::as_str) == Some("issuer-verify")
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
    // gr_u: group random (issuer-provided nonce, same size as et_u)
    // The DAA host proves: SPHINCS+ sig is valid over et_u || gr_u
    use rand::RngCore;
    use rand_core::SeedableRng;
    let deterministic = std::env::var("DAA_DETERMINISTIC").ok().as_deref() == Some("1");
    let mut deterministic_rng = rand_chacha::ChaCha20Rng::from_seed([11u8; 32]);
    let mut et_u = vec![0u8; ET_GR_BYTES];
    let mut issuer_nonce = vec![0u8; ET_GR_BYTES];
    if deterministic {
        deterministic_rng.fill_bytes(&mut et_u);
        deterministic_rng.fill_bytes(&mut issuer_nonce);
    } else {
        rand::thread_rng().fill_bytes(&mut et_u);
        rand::thread_rng().fill_bytes(&mut issuer_nonce);
    }

    // msg fed to SPHINCS+ sign = et_u || gr_u
    // SPHINCS+ internally applies hash_message (acting as H3) to derive mt_u || idx
    let mut msg = Vec::with_capacity(2 * ET_GR_BYTES);
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
        "DAA message: et_u={}B || gr_u={}B, AES key={}B, hk={}B",
        ET_GR_BYTES,
        ET_GR_BYTES,
        S_BYTES,
        if ET_GR_BYTES == 16 { 16 } else { 32 }
    );

    // ── 4) AES hook witnesses ─────────────────────────────────────────────
    // s is the TPM signing key (also used as AES key for the hook commitment)
    let mut s = vec![0u8; S_BYTES];
    if deterministic {
        deterministic_rng.fill_bytes(&mut s);
    } else {
        rand::thread_rng().fill_bytes(&mut s);
    }

    let hk = aes_hook(&s, &et_u);

    // ── 5) Build guest env ────────────────────────────────────────────────
    let seg_po2: u32 = std::env::var("RISC0_SEGMENT_LIMIT_PO2")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(21);

    // All values are private witnesses fed to the zkVM guest.
    // The guest reconstructs msg = et_u || gr_u internally — et_u is never exposed.
    // Order must match guest env::read() order exactly.
    let env = ExecutorEnv::builder()
        .segment_limit_po2(seg_po2)
        .write_slice(&pk)
        .write_slice(&sig)
        .write_slice(&hk)
        .write_slice(&s)
        .write_slice(&et_u)
        .write_slice(&issuer_nonce)
        .build()
        .unwrap();

    // ── 6) Prove ──────────────────────────────────────────────────────────
    let prover = default_prover();
    let backend_hash =
        std::env::var("RISC0_BACKEND_HASH").unwrap_or_else(|_| "sha-256".to_string());
    let opts = ProverOpts::composite()
        .with_hashfn(backend_hash.clone())
        .with_receipt_kind(ReceiptKind::Composite);

    println!(
        "start proving (seg_po2={}, backend hashfn={})",
        seg_po2, opts.hashfn
    );
    let t0 = Instant::now();
    let prove_info = prover.prove_with_opts(env, GUEST_ELF, &opts).unwrap();
    let prove_ms = t0.elapsed().as_millis();
    let stats = prove_info.stats.clone();

    let receipt = prove_info.receipt;
    print_and_check_segment_hashes(&receipt, &backend_hash);
    let journal = receipt.journal.bytes.as_slice();
    assert_eq!(&journal[..4], &1u32.to_le_bytes());
    assert_eq!(&journal[4..4 + hk.len()], hk.as_slice());
    assert_eq!(
        &journal[4 + hk.len()..4 + hk.len() + pk.len()],
        pk.as_slice()
    );
    #[cfg(not(sphincs_profile))]
    assert_eq!(journal.len(), 4 + hk.len() + pk.len());
    #[cfg(sphincs_profile)]
    print_profile(&journal[4 + hk.len() + pk.len()..]);

    let proof_bytes = risc0_zkvm::serde::to_vec(&receipt).unwrap().len() * core::mem::size_of::<u32>();
    println!(
        "done proving, prover time = {} ms, proof size = {} bytes",
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

    // ── 7) Verify ─────────────────────────────────────────────────────────
    let t1 = Instant::now();
    receipt.verify(GUEST_ID).unwrap();
    let verify_ms = t1.elapsed().as_millis();
    println!("verify ok, verifier time = {} ms", verify_ms);
}

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
        _ => unreachable!(),
    }
}

fn protocol_issuer_keygen(output_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let pk_bytes = unsafe { sphincs_pk_bytes() };
    let sk_bytes = unsafe { sphincs_sk_bytes() };
    let mut pk = vec![0u8; pk_bytes];
    let mut sk = vec![0u8; sk_bytes];
    let t0 = Instant::now();
    let ret = unsafe { crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) };
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
    let sig_bytes = unsafe { sphincs_sig_bytes() };
    let mut signed = vec![0u8; sig_bytes + msg.len() + 64];
    let mut signed_len = 0u64;
    let t0 = Instant::now();
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
    write_parts(output_path, &[&signed[..sig_bytes]])?;
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
        crypto_sign_verify(
            parts[2].as_ptr(),
            parts[2].len(),
            parts[1].as_ptr(),
            parts[1].len(),
            parts[0].as_ptr(),
        )
    };
    println!("accepted={}", if ret == 0 { 1 } else { 0 });
    println!("verifier_ms={}", t0.elapsed().as_millis());
    Ok(())
}

struct ProtocolInput {
    issuer_pk: Vec<u8>,
    credential_sig: Vec<u8>,
    hk: Vec<u8>,
    s: Vec<u8>,
    et_u: Vec<u8>,
    issuer_nonce: Vec<u8>,
}

fn protocol_prove(
    input_path: &Path,
    receipt_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let input = read_protocol_input(input_path)?;

    let env = ExecutorEnv::builder()
        .segment_limit_po2(
            std::env::var("RISC0_SEGMENT_LIMIT_PO2")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(21),
        )
        .write_slice(&input.issuer_pk)
        .write_slice(&input.credential_sig)
        .write_slice(&input.hk)
        .write_slice(&input.s)
        .write_slice(&input.et_u)
        .write_slice(&input.issuer_nonce)
        .build()?;

    let backend_hash =
        std::env::var("RISC0_BACKEND_HASH").unwrap_or_else(|_| "sha-256".to_string());
    let opts = ProverOpts::composite()
        .with_hashfn(backend_hash)
        .with_receipt_kind(ReceiptKind::Composite);
    let t0 = Instant::now();
    let prove_info = default_prover().prove_with_opts(env, GUEST_ELF, &opts)?;
    let prove_ms = t0.elapsed().as_millis();
    let stats = prove_info.stats.clone();
    let receipt = prove_info.receipt;
    check_protocol_journal(&receipt, &input.issuer_pk, &input.hk)?;
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

fn protocol_verify(
    input_path: &Path,
    receipt_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let input = read_protocol_input(input_path)?;
    let receipt = read_receipt_words(receipt_path)?;
    let t0 = Instant::now();
    receipt.verify(GUEST_ID)?;
    let verify_ms = t0.elapsed().as_millis();
    check_protocol_journal(&receipt, &input.issuer_pk, &input.hk)?;
    println!("accepted=1");
    println!("verifier_ms={verify_ms}");
    Ok(())
}

fn check_protocol_journal(
    receipt: &Receipt,
    issuer_pk: &[u8],
    hk: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let journal = receipt.journal.bytes.as_slice();
    if journal.len() < 4 + hk.len() + issuer_pk.len() {
        return Err("journal is too short".into());
    }
    if &journal[..4] != 1u32.to_le_bytes().as_slice() {
        return Err("journal status is not ok".into());
    }
    if &journal[4..4 + hk.len()] != hk {
        return Err("journal hk mismatch".into());
    }
    if &journal[4 + hk.len()..4 + hk.len() + issuer_pk.len()] != issuer_pk {
        return Err("journal issuer pk mismatch".into());
    }
    Ok(())
}

fn read_protocol_input(path: &Path) -> Result<ProtocolInput, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    let mut pos = 0usize;
    Ok(ProtocolInput {
        issuer_pk: read_part(&bytes, &mut pos)?,
        credential_sig: read_part(&bytes, &mut pos)?,
        hk: read_part(&bytes, &mut pos)?,
        s: read_part(&bytes, &mut pos)?,
        et_u: read_part(&bytes, &mut pos)?,
        issuer_nonce: read_part(&bytes, &mut pos)?,
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
        _ => {
            panic!("expected composite receipt");
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
