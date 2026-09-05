//! External RISC0 runner integration for the alternative Setup-only WOTS proof.
use super::*;

pub(super) struct FixedWotsMeasurement {
    pub proof: ProofArtifact,
    pub prove: Duration,
    pub verify: Duration,
    pub user_cycles: u64,
    pub total_cycles: u64,
    pub segments: usize,
}

pub(super) struct PrivateFiles {
    pub dir: PathBuf,
}

impl PrivateFiles {
    /// Creates a private temporary directory before writing any issuer witness material.
    pub(super) fn new() -> DaaResult<Self> {
        let stamp = HOST_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("sedaa-wots-{}-{stamp}", std::process::id()));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(&dir)
            .map_err(|_| DaaError::ExternalHostProof)?;
        Ok(Self { dir })
    }
}

impl Drop for PrivateFiles {
    /// Removes only this invocation's input/receipt files, including on error paths.
    fn drop(&mut self) {
        for name in ["input", "receipt"] {
            let _ = std::fs::remove_file(self.dir.join(name));
        }
        let _ = std::fs::remove_dir(&self.dir);
    }
}

/// Runs and times pi_I inside the host process, excluding Cargo and subprocess startup.
pub(super) fn fixed_wots_prove_external(
    config: &ProtocolConfig,
    native: &IssuerAnchorNative,
) -> DaaResult<FixedWotsMeasurement> {
    let files = PrivateFiles::new()?;
    let input = files.dir.join("input");
    let receipt = files.dir.join("receipt");
    write_length_prefixed_parts(
        &input,
        &[&native.public_a, &native.certificate, &native.witness],
    )
    .map_err(|_| DaaError::ExternalHostProof)?;
    let mut cmd = host_cargo_command(config)?;
    cmd.arg("issuer-wots-prove").arg(&input).arg(&receipt);
    let output = cmd.output().map_err(|_| DaaError::ExternalHostProof)?;
    let text = command_text(&output);
    if !output.status.success() {
        eprintln!("fixed WOTS pi_I failed:\n{text}");
        return Err(DaaError::InvalidIssuerAnchor);
    }
    let metric = |key| parse_metric_u128(&text, key).ok_or(DaaError::ExternalHostProof);
    let bytes = std::fs::read(receipt).map_err(|_| DaaError::ExternalHostProof)?;
    let context = issuer_anchor_context(config, &native.public_a, &native.certificate);
    Ok(FixedWotsMeasurement {
        proof: ProofArtifact {
            kind: "pi_i".into(),
            backend: format!("risc0-fixed-top-wots-{}", config.backend_hash),
            statement_hash: context,
            proof_bytes: bytes,
            seal_bytes: Some(metric("seal_bytes")? as usize),
        },
        prove: Duration::from_micros(metric("prover_us")? as u64),
        verify: Duration::from_micros(metric("verifier_us")? as u64),
        user_cycles: metric("guest_user_cycles")? as u64,
        total_cycles: metric("guest_total_cycles")? as u64,
        segments: metric("segments")? as usize,
    })
}

/// Verifies the selected RISC0 statement using public material only, never the WOTS witness.
pub(super) fn fixed_wots_verify_external(
    config: &ProtocolConfig,
    native: &IssuerAnchorNative,
    proof: &ProofArtifact,
) -> bool {
    let run = || -> DaaResult<bool> {
        let expected = issuer_anchor_context(config, &native.public_a, &native.certificate);
        if proof.kind != "pi_i"
            || proof.statement_hash != expected
            || native.certificate.get(16..16 + config.security.key_bytes())
                != Some(native.anchor_value.as_slice())
        {
            eprintln!("fixed WOTS pi_I Rust statement binding mismatch");
            return Ok(false);
        }
        let files = PrivateFiles::new()?;
        let input = files.dir.join("input");
        let receipt = files.dir.join("receipt");
        write_length_prefixed_parts(&input, &[&native.public_a, &native.certificate])
            .map_err(|_| DaaError::ExternalHostProof)?;
        std::fs::write(&receipt, &proof.proof_bytes).map_err(|_| DaaError::ExternalHostProof)?;
        let mut cmd = host_cargo_command(config)?;
        cmd.arg("issuer-wots-verify").arg(input).arg(receipt);
        let output = cmd.output().map_err(|_| DaaError::ExternalHostProof)?;
        if !output.status.success() {
            eprintln!(
                "fixed WOTS pi_I verification failed:\n{}",
                command_text(&output)
            );
        }
        Ok(output.status.success()
            && parse_metric_bool(&command_text(&output), "accepted") == Some(true))
    };
    run().unwrap_or(false)
}
