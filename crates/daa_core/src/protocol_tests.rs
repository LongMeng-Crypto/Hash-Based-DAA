use super::*;

#[test]
#[ignore = "requires the RISC0 toolchains and a real CPU or GPU prover"]
// Checks enrollment, credential binding, message binding, and malformed inputs with real proofs.
fn real_protocol_rejects_tampering() {
    let config = ProtocolConfig::default()
        .with_params("sha2-128f")
        .with_tpm_backend(TpmBackend::Sha2)
        .with_tpm_sha_scheme(TpmShaScheme::Cdenw23Ours5F)
        .with_host_scheme(HostScheme::FSphincs)
        .with_risc0_segment_limit_po2(Some(20));
    let mut trace = BenchmarkTrace::new();
    let mut issuer = setup(config, &mut trace).unwrap();
    let mut bad = issuer.clone();
    bad.issuer_anchor.pi_i.proof_bytes[0] ^= 1;
    assert!(join(&mut bad, 1, &mut trace).is_err());
    let mut bad = issuer.clone();
    bad.issuer_anchor.certificate[20] ^= 1;
    assert!(join(&mut bad, 1, &mut trace).is_err());
    let mut bad = issuer.clone();
    bad.issuer_anchor.anchor_value[0] ^= 1;
    assert!(join(&mut bad, 1, &mut trace).is_err());
    let member = join(&mut issuer, 1, &mut trace).unwrap();
    assert!(matches!(
        join(&mut issuer, 1, &mut trace),
        Err(DaaError::DuplicateMember)
    ));
    let signature = sign(
        &issuer,
        &member.tpm_state,
        &member.host_state,
        b"message",
        b"basename",
        &mut trace,
    )
    .unwrap()
    .signature;
    assert!(verify(
        &issuer,
        &issuer.revocation_state,
        b"message",
        b"basename",
        &signature,
        &mut trace
    )
    .unwrap());
    assert!(verify(
        &issuer,
        &issuer.revocation_state,
        b"changed",
        b"basename",
        &signature,
        &mut trace
    )
    .is_err());
    assert!(verify(
        &issuer,
        &issuer.revocation_state,
        b"message",
        b"other",
        &signature,
        &mut trace
    )
    .is_err());
    let changed_context = message_prime(&issuer.config, b"changed", &signature.rho);
    assert!(verify_host_risc0_128s(
        &issuer.config,
        &signature.pi_host,
        &issuer.issuer_keys.mpk,
        &signature.hk,
        &signature.cet,
        &changed_context
    )
    .is_err());
    let mut bad = signature.clone();
    bad.hk.clear();
    assert!(verify(
        &issuer,
        &issuer.revocation_state,
        b"message",
        b"basename",
        &bad,
        &mut trace
    )
    .is_err());
    let mut bad = signature.clone();
    bad.pi_tpm.proof_bytes[0] ^= 1;
    assert!(verify(
        &issuer,
        &issuer.revocation_state,
        b"message",
        b"basename",
        &bad,
        &mut trace
    )
    .is_err());
    let mut bad = signature.clone();
    bad.pi_host.proof_bytes[20] ^= 1;
    assert!(verify(
        &issuer,
        &issuer.revocation_state,
        b"message",
        b"basename",
        &bad,
        &mut trace
    )
    .is_err());
    let mut cpu = issuer.clone();
    cpu.config.proof_mode = ProofMode::RealTpm;
    let mut bad_host = member.host_state.clone();
    bad_host.credential.sigma[0] ^= 1;
    assert!(sign(
        &cpu,
        &member.tpm_state,
        &bad_host,
        b"message",
        b"basename",
        &mut trace
    )
    .is_err());
}
