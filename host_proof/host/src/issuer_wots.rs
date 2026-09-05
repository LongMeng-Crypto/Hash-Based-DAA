//! Setup-time proof of a complete top WOTS+ key, independent of master-seed consistency.
use super::*;
use methods::{ISSUER_WOTS_GUEST_ELF, ISSUER_WOTS_GUEST_ID};

extern "C" {
    fn sphincs_issuer_wots_certificate_bytes() -> usize;
    fn sphincs_issuer_wots_witness_bytes() -> usize;
    fn sphincs_issuer_wots_generate(
        cert: *mut u8,
        cert_len: usize,
        witness: *mut u8,
        witness_len: usize,
        pk: *const u8,
        sk: *const u8,
    ) -> i32;
    fn sphincs_issuer_wots_verify(cert: *const u8, len: usize, pk: *const u8) -> i32;
    fn sphincs_issuer_wots_relation(
        cert: *const u8,
        len: usize,
        pk: *const u8,
        witness: *const u8,
        witness_len: usize,
    ) -> i32;
    fn sphincs_issuer_wots_capability_test(
        cert: *const u8,
        pk: *const u8,
        witness: *const u8,
    ) -> i32;
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Parses the Setup-only selector without changing the credential or host-signature protocol.
pub(super) fn enabled() -> bool {
    match env::var("DAA_ISSUER_ANCHOR_MODE").as_deref() {
        Err(_) | Ok("seed-dual") => false,
        Ok("fixed-top-wots") => true,
        Ok(other) => panic!("unsupported DAA_ISSUER_ANCHOR_MODE={other}"),
    }
}

/// Rejects credential/hash combinations not implemented by the fixed-top WOTS relation.
fn supported() -> Result<()> {
    if credential_is_fsphincs()
        || env!("SPHINCS_HASH_BACKEND") != "sha2"
        || env!("SPHINCS_THASH") != "simple"
    {
        return Err("fixed-top-wots requires standard SHA2-simple SPHINCS+".into());
    }
    Ok(())
}

/// Builds the compressed public certificate and checks native extraction capability.
pub(super) fn generate(pk: &[u8], sk: &[u8]) -> Result<NativeAnchorMaterial> {
    supported()?;
    if pk.len() != credential_pk_bytes() || sk.len() != credential_sk_bytes() {
        return Err("fixed WOTS key size mismatch".into());
    }
    let mut certificate = vec![0; unsafe { sphincs_issuer_wots_certificate_bytes() }];
    let mut witness = vec![0; unsafe { sphincs_issuer_wots_witness_bytes() }];
    let started = Instant::now();
    if unsafe {
        sphincs_issuer_wots_generate(
            certificate.as_mut_ptr(),
            certificate.len(),
            witness.as_mut_ptr(),
            witness.len(),
            pk.as_ptr(),
            sk.as_ptr(),
        )
    } != 0
    {
        return Err("fixed WOTS anchor generation failed".into());
    }
    let generation_us = started.elapsed().as_micros();
    let started = Instant::now();
    check_certificate(pk, &certificate)?;
    let verify_us = started.elapsed().as_micros();
    // Native differential and negative tests are excluded from benchmark timers.
    let mut wrong = witness.clone();
    wrong[0] ^= 1;
    if unsafe {
        sphincs_issuer_wots_relation(
            certificate.as_ptr(),
            certificate.len(),
            pk.as_ptr(),
            wrong.as_ptr(),
            wrong.len(),
        )
    } == 0
    {
        return Err("mutated WOTS witness accepted".into());
    }
    for offset in [0, 8, 12, 15, 16, certificate.len() - 1] {
        let mut wrong = certificate.clone();
        wrong[offset] ^= 1;
        if check_certificate(pk, &wrong).is_ok() {
            return Err("mutated WOTS certificate accepted".into());
        }
    }
    if unsafe {
        sphincs_issuer_wots_capability_test(certificate.as_ptr(), pk.as_ptr(), witness.as_ptr())
    } != 0
    {
        return Err("WOTS-only signing capability test failed".into());
    }
    println!("wots_only_signing_test=ok");
    Ok(NativeAnchorMaterial {
        public_a: pk.to_vec(),
        public_b: Vec::new(),
        anchor_value: certificate[16..16 + pk.len() / 2].to_vec(),
        certificate,
        witness,
        generation_us,
        verify_us,
    })
}

/// Checks the public top-tree certificate without reading any secret WOTS material.
pub(super) fn check_certificate(pk: &[u8], cert: &[u8]) -> Result<()> {
    supported()?;
    if pk.len() != credential_pk_bytes()
        || unsafe { sphincs_issuer_wots_verify(cert.as_ptr(), cert.len(), pk.as_ptr()) } != 0
    {
        return Err("invalid fixed WOTS public certificate".into());
    }
    Ok(())
}

/// Constructs the exact public journal; full bytes bind the image, key, index and authentication path.
fn journal(pk: &[u8], cert: &[u8]) -> Vec<u8> {
    [b"DAA-PI-I-FIXED-WOTS-v1".as_slice(), pk, cert].concat()
}

/// Verifies the proof, complete public statement and top authentication certificate.
fn verify_receipt(receipt: &Receipt, pk: &[u8], cert: &[u8], hash: &str) -> Result<()> {
    // pi_I.Verify = public PathCheck(pk, cert) AND PoK[FullWotsKey(pk, cert.leaf)].
    // Receipt::verify alone is not sufficient; the complete journal must match the same pk/cert.
    if !matches!(
        &receipt.inner,
        InnerReceipt::Composite(_) | InnerReceipt::Succinct(_)
    ) {
        return Err("pi_I requires a real Composite or Succinct receipt".into());
    }
    check_certificate(pk, cert)?;
    if receipt.journal.bytes != journal(pk, cert) {
        return Err("fixed WOTS pi_I statement mismatch".into());
    }
    receipt.verify_with_context(
        &verifier_context_for_hashfn(hash, DEFAULT_MAX_PO2 as u32),
        ISSUER_WOTS_GUEST_ID,
    )?;
    Ok(())
}

/// Proves the private complete WOTS key and reports timings excluding compilation and serialization.
pub(super) fn prove(input: &Path, output: &Path) -> Result<()> {
    supported()?;
    if ISSUER_WOTS_GUEST_ELF.is_empty() {
        return Err("unset RISC0_SKIP_BUILD to build issuer_wots_guest".into());
    }
    let parts = read_parts(input)?;
    if parts.len() != 3 {
        return Err("issuer-wots-prove requires pk, certificate, WOTS witness".into());
    }
    let (pk, cert, witness) = (&parts[0], &parts[1], &parts[2]);
    check_certificate(pk, cert)?;
    if witness.len() != unsafe { sphincs_issuer_wots_witness_bytes() } {
        return Err("wrong complete WOTS witness length".into());
    }
    let seg_po2 = env::var("RISC0_SEGMENT_LIMIT_PO2")
        .unwrap_or_else(|_| "20".into())
        .parse::<u32>()?;
    if !(14..=22).contains(&seg_po2) {
        return Err("segment exponent must be 14..22".into());
    }
    let hash = env::var("RISC0_BACKEND_HASH").unwrap_or_else(|_| "sha-256".into());
    let environment = ExecutorEnv::builder()
        .segment_limit_po2(seg_po2)
        .write_slice(pk)
        .write_slice(cert)
        .write_slice(witness)
        .build()?;
    let started = Instant::now();
    let info = default_prover().prove_with_opts(
        environment,
        ISSUER_WOTS_GUEST_ELF,
        &prover_opts_from_env(hash.clone()),
    )?;
    let prover_us = started.elapsed().as_micros();
    // No identity is necessary: the full-chain workload and anchor index are public and fixed.
    let started = Instant::now();
    verify_receipt(&info.receipt, pk, cert, &hash)?;
    let verifier_us = started.elapsed().as_micros();
    write_receipt_words(output, &info.receipt)?;
    let proof_bytes = fs::metadata(output)?.len();
    println!("accepted=1\nprover_us={prover_us}\nverifier_us={verifier_us}");
    println!(
        "proof_bytes={proof_bytes}\nseal_bytes={}",
        info.receipt.seal_size()
    );
    println!(
        "guest_user_cycles={}\nguest_total_cycles={}\nsegments={}",
        info.stats.user_cycles, info.stats.total_cycles, info.stats.segments
    );
    println!(
        "receipt_kind={:?}\nbackend={hash}\nsegment_po2={seg_po2}",
        receipt_kind_from_env()
    );
    print_and_check_segment_hashes(&info.receipt, &hash);
    // Reject changed statements and a damaged seal, outside the measured verification.
    let mut bad_pk = pk.clone();
    bad_pk[0] ^= 1;
    if verify_receipt(&info.receipt, &bad_pk, cert, &hash).is_ok() {
        return Err("wrong issuer accepted".into());
    }
    for offset in [8, 15, 16, cert.len() - 1] {
        let mut bad_cert = cert.clone();
        bad_cert[offset] ^= 1;
        if verify_receipt(&info.receipt, pk, &bad_cert, &hash).is_ok() {
            return Err("changed pi_I public certificate accepted".into());
        }
    }
    let mut bad = info.receipt.clone();
    match &mut bad.inner {
        InnerReceipt::Composite(inner) => {
            inner.segments[0].seal[0] ^= 1;
        }
        InnerReceipt::Succinct(inner) => {
            inner.seal[0] ^= 1;
        }
        _ => return Err("unexpected proof kind".into()),
    }
    if verify_receipt(&bad, pk, cert, &hash).is_ok() {
        return Err("damaged pi_I accepted".into());
    }
    println!("proof_mutation_test=ok");
    Ok(())
}

/// Independently verifies a serialized pi_I using only the public key and certificate.
pub(super) fn verify(input: &Path, receipt_path: &Path) -> Result<()> {
    let parts = read_parts(input)?;
    if parts.len() != 2 {
        return Err("issuer-wots-verify requires pk and certificate".into());
    }
    let receipt = read_receipt_words(receipt_path)?;
    let hash = env::var("RISC0_BACKEND_HASH").unwrap_or_else(|_| "sha-256".into());
    let started = Instant::now();
    verify_receipt(&receipt, &parts[0], &parts[1], &hash)?;
    println!("accepted=1\nverifier_us={}", started.elapsed().as_micros());
    Ok(())
}
