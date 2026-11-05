use super::*;

unsafe extern "C" {
    fn daa_rdm_join_proof_size(fast: i32) -> usize;
    fn daa_rdm_sign_proof_size(fast: i32) -> usize;
    fn daa_rdm_join_prove(
        fast: i32,
        sk: *const u8,
        gid: *const u8,
        et: *const u8,
        msg: *const u8,
        msg_len: usize,
        proof: *mut u8,
        proof_len: *mut usize,
    ) -> i32;
    fn daa_rdm_join_verify(
        fast: i32,
        gid: *const u8,
        et: *const u8,
        msg: *const u8,
        msg_len: usize,
        proof: *const u8,
        proof_len: usize,
    ) -> i32;
    fn daa_rdm_sign_prove(
        fast: i32,
        sk: *const u8,
        s: *const u8,
        lid: *const u8,
        gid: *const u8,
        slt: *const u8,
        hk: *const u8,
        msg: *const u8,
        msg_len: usize,
        proof: *mut u8,
        proof_len: *mut usize,
    ) -> i32;
    fn daa_rdm_sign_verify(
        fast: i32,
        lid: *const u8,
        gid: *const u8,
        slt: *const u8,
        hk: *const u8,
        msg: *const u8,
        msg_len: usize,
        proof: *const u8,
        proof_len: usize,
    ) -> i32;
}

// Evaluates the TPM primitive with fixed-width inputs.
pub(super) fn eval(key: &[u8], input: &[u8]) -> Bytes {
    rijndael::eval(
        key.try_into().expect("32-byte Rijndael key"),
        input.try_into().expect("32-byte Rijndael block"),
    )
    .to_vec()
}

// Checks native input widths and supported proof security.
fn valid(config: &ProtocolConfig, inputs: &[&[u8]]) -> bool {
    config.security == SecurityLevel::L128 && inputs.iter().all(|value| value.len() == 32)
}

// Selects the VOLEith parameter profile.
fn fast(config: &ProtocolConfig) -> i32 {
    i32::from(config.tpm_sha_profile == TpmShaProfile::Fast)
}

// Encodes a context-bound Rijndael proof artifact.
fn artifact(
    config: &ProtocolConfig,
    kind: &str,
    statement: &[&[u8]],
    proof: Bytes,
) -> ProofArtifact {
    ProofArtifact {
        kind: kind.into(),
        backend: format!(
            "voleith-rijndael256-128{}-{}",
            config.tpm_sha_profile.name(),
            kind
        ),
        statement_hash: sha2_hash(SecurityLevel::L128, statement),
        proof_bytes: proof,
        seal_bytes: None,
    }
}

// Proves the Join token relation using one Rijndael evaluation.
pub(super) fn prove_join(
    config: &ProtocolConfig,
    sk: &[u8],
    gid: &[u8],
    et: &[u8],
    msg: &[u8],
) -> DaaResult<ProofArtifact> {
    if !valid(config, &[sk, gid, et]) || eval(sk, gid) != et {
        return Err(DaaError::InvalidJoinProof);
    }
    let mut proof = vec![0; unsafe { daa_rdm_join_proof_size(fast(config)) }];
    let mut len = proof.len();
    let result = unsafe {
        daa_rdm_join_prove(
            fast(config),
            sk.as_ptr(),
            gid.as_ptr(),
            et.as_ptr(),
            msg.as_ptr(),
            msg.len(),
            proof.as_mut_ptr(),
            &mut len,
        )
    };
    if result != 0 || len > proof.len() {
        return Err(DaaError::InvalidJoinProof);
    }
    proof.truncate(len);
    Ok(artifact(config, "pi_join", &[gid, et, msg], proof))
}

// Verifies the context-bound Join token proof.
pub(super) fn verify_join(
    config: &ProtocolConfig,
    proof: &ProofArtifact,
    gid: &[u8],
    et: &[u8],
    msg: &[u8],
) -> bool {
    valid(config, &[gid, et])
        && proof.statement_hash == sha2_hash(SecurityLevel::L128, &[gid, et, msg])
        && unsafe {
            daa_rdm_join_verify(
                fast(config),
                gid.as_ptr(),
                et.as_ptr(),
                msg.as_ptr(),
                msg.len(),
                proof.proof_bytes.as_ptr(),
                proof.proof_bytes.len(),
            ) == 0
        }
}

// Proves the joint token, pseudonym, and credential hook relations.
#[allow(clippy::too_many_arguments)]
pub(super) fn prove_sign(
    config: &ProtocolConfig,
    lid: &[u8],
    gid: &[u8],
    sk: &[u8],
    s: &[u8],
    msg: &[u8],
    et: &[u8],
    slt: &[u8],
    hk: &[u8],
) -> DaaResult<ProofArtifact> {
    if !valid(config, &[lid, gid, sk, s, et, slt, hk])
        || eval(sk, gid) != et
        || eval(sk, lid) != slt
        || eval(s, et) != hk
    {
        return Err(DaaError::InvalidTpmProof);
    }
    let mut proof = vec![0; unsafe { daa_rdm_sign_proof_size(fast(config)) }];
    let mut len = proof.len();
    let result = unsafe {
        daa_rdm_sign_prove(
            fast(config),
            sk.as_ptr(),
            s.as_ptr(),
            lid.as_ptr(),
            gid.as_ptr(),
            slt.as_ptr(),
            hk.as_ptr(),
            msg.as_ptr(),
            msg.len(),
            proof.as_mut_ptr(),
            &mut len,
        )
    };
    if result != 0 || len > proof.len() {
        return Err(DaaError::InvalidTpmProof);
    }
    proof.truncate(len);
    Ok(artifact(config, "pi_tpm", &[lid, gid, slt, hk, msg], proof))
}

// Verifies the context-bound joint TPM proof.
pub(super) fn verify_sign(
    config: &ProtocolConfig,
    proof: &ProofArtifact,
    lid: &[u8],
    gid: &[u8],
    slt: &[u8],
    hk: &[u8],
    msg: &[u8],
) -> bool {
    valid(config, &[lid, gid, slt, hk])
        && proof.statement_hash == sha2_hash(SecurityLevel::L128, &[lid, gid, slt, hk, msg])
        && unsafe {
            daa_rdm_sign_verify(
                fast(config),
                lid.as_ptr(),
                gid.as_ptr(),
                slt.as_ptr(),
                hk.as_ptr(),
                msg.as_ptr(),
                msg.len(),
                proof.proof_bytes.as_ptr(),
                proof.proof_bytes.len(),
            ) == 0
        }
}

#[cfg(test)]
mod tests {
    use super::*;
    unsafe extern "C" {
        fn daa_rdm_eval(key: *const u8, input: *const u8, output: *mut u8);
    }

    #[test]
    // Checks portable guest evaluation against native Rijndael.
    fn portable_matches_native() {
        let mut rng = DeterministicRng::new(809);
        for _ in 0..32 {
            let key = rng.bytes(32);
            let input = rng.bytes(32);
            let mut out = [0u8; 32];
            unsafe {
                daa_rdm_eval(key.as_ptr(), input.as_ptr(), out.as_mut_ptr());
            }
            assert_eq!(eval(&key, &input), out);
        }
    }

    #[test]
    // Checks both proof profiles and rejection of altered statements and witnesses.
    fn proofs_bind_statements() {
        for params in ["sha2-128s", "sha2-128f"] {
            let config = ProtocolConfig::default()
                .with_params(params)
                .with_tpm_backend(TpmBackend::Rijndael);
            let sk = [37u8; 32];
            let s = [93u8; 32];
            let gid = [4u8; 32];
            let lid = [7u8; 32];
            let et = eval(&sk, &gid);
            let slt = eval(&sk, &lid);
            let hk = eval(&s, &et);
            let join = prove_join(&config, &sk, &gid, &et, b"join").unwrap();
            assert!(verify_join(&config, &join, &gid, &et, b"join"));
            assert!(!verify_join(&config, &join, &gid, &et, b"changed"));
            let mut wrong_et = et.clone();
            wrong_et[0] ^= 1;
            assert!(prove_join(&config, &sk, &gid, &wrong_et, b"join").is_err());
            let proof =
                prove_sign(&config, &lid, &gid, &sk, &s, b"message", &et, &slt, &hk).unwrap();
            assert!(verify_sign(
                &config, &proof, &lid, &gid, &slt, &hk, b"message"
            ));
            assert!(!verify_sign(
                &config, &proof, &lid, &gid, &slt, &hk, b"changed"
            ));
            let mut wrong = hk.clone();
            wrong[0] ^= 1;
            assert!(!verify_sign(
                &config, &proof, &lid, &gid, &slt, &wrong, b"message"
            ));
            assert!(
                prove_sign(&config, &lid, &gid, &sk, &s, b"message", &et, &slt, &wrong).is_err()
            );
            assert!(!verify_sign(
                &config,
                &proof,
                &lid[..16],
                &gid,
                &slt,
                &hk,
                b"message"
            ));
        }
        assert!(ProtocolConfig::default()
            .with_params("sha2-192s")
            .with_tpm_backend(TpmBackend::Rijndael)
            .ensure_real_supported()
            .is_err());
    }
}
