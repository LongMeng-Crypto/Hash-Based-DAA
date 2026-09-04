use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256, Sha384, Sha512};

pub type Bytes = Vec<u8>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    L128,
    L192,
    L256,
}

impl SecurityLevel {
    /// Derives the symmetric security level from a parameter-set name.
    pub fn from_name(name: &str) -> Self {
        if name.contains("192") {
            Self::L192
        } else if name.contains("256") {
            Self::L256
        } else {
            Self::L128
        }
    }

    /// Returns the byte length of AES/FAEST keys at this security level.
    pub fn key_bytes(self) -> usize {
        match self {
            Self::L128 => 16,
            Self::L192 => 24,
            Self::L256 => 32,
        }
    }

    /// Returns the byte length of public DAA tokens at this security level.
    pub fn token_bytes(self) -> usize {
        match self {
            Self::L128 => 16,
            Self::L192 | Self::L256 => 32,
        }
    }

    /// Returns the full SHA-2 digest length used by the TPM-SHA backend.
    pub fn sha_digest_bytes(self) -> usize {
        match self {
            Self::L128 => 32,
            Self::L192 => 48,
            Self::L256 => 64,
        }
    }

    /// Returns the numeric VOLEith security selector used by the C ABI.
    fn bits(self) -> u32 {
        match self {
            Self::L128 => 128,
            Self::L192 => 192,
            Self::L256 => 256,
        }
    }
}

/// Selects the FAEST-style size/speed tradeoff at a fixed security level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmShaProfile {
    Small,
    Fast,
}

impl TpmShaProfile {
    pub fn from_name(name: &str) -> Self {
        if name.ends_with('f') {
            Self::Fast
        } else {
            Self::Small
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Small => "s",
            Self::Fast => "f",
        }
    }

    fn code(self) -> u32 {
        match self {
            Self::Small => 1,
            Self::Fast => 2,
        }
    }
}

/// Selects the legacy AES/FAEST TPM relation or the SHA-2/VOLEith relation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmBackend {
    Aes,
    Sha2,
}

/// Selects the SHA-2 TPM signing relation without changing the Join relation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmShaScheme {
    Ours3F,
    Cdenw23Ours5F,
}

impl TpmShaScheme {
    pub fn from_name(name: &str) -> DaaResult<Self> {
        match name {
            "ours" | "ours-3f" | "3f" => Ok(Self::Ours3F),
            "chen23" | "cdenw23" | "cdenw23-5f" | "5f" => Ok(Self::Cdenw23Ours5F),
            _ => Err(DaaError::UnsupportedTpmShaScheme),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Ours3F => "ours",
            Self::Cdenw23Ours5F => "chen23",
        }
    }
}

/// Selects the issuer credential verified inside the RISC0 host proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialScheme {
    SphincsPlus,
    FSphincsPlus,
}

impl CredentialScheme {
    pub fn from_name(name: &str) -> DaaResult<Self> {
        match name {
            "sphincs" | "sphincs+" => Ok(Self::SphincsPlus),
            "fsphincs" | "f-sphincs" | "f-sphincs+" => Ok(Self::FSphincsPlus),
            _ => Err(DaaError::UnsupportedCredentialScheme),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::SphincsPlus => "sphincs",
            Self::FSphincsPlus => "fsphincs",
        }
    }
}

impl TpmBackend {
    pub fn from_name(name: &str) -> DaaResult<Self> {
        match name {
            "aes" | "legacy-aes" => Ok(Self::Aes),
            "sha" | "sha2" | "sha-2" => Ok(Self::Sha2),
            _ => Err(DaaError::UnsupportedTpmBackend),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Aes => "aes",
            Self::Sha2 => "sha2",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProtocolConfig {
    pub sphincs_params: String,
    pub backend_hash: String,
    pub security: SecurityLevel,
    pub deterministic_seed: u64,
    pub proof_mode: ProofMode,
    pub tpm_backend: TpmBackend,
    pub tpm_sha_scheme: TpmShaScheme,
    pub tpm_sha_profile: TpmShaProfile,
    pub credential_scheme: CredentialScheme,
    pub risc0_segment_limit_po2: Option<u32>,
}

impl Default for ProtocolConfig {
    /// Builds the default SHA2-128s/SHA-256 real-proof configuration.
    fn default() -> Self {
        let sphincs_params = "sha2-128s".to_string();
        Self {
            security: SecurityLevel::from_name(&sphincs_params),
            sphincs_params,
            backend_hash: "sha-256".to_string(),
            deterministic_seed: 0xdaa5_eeda_2026_0705,
            proof_mode: ProofMode::Real128s,
            tpm_backend: TpmBackend::Aes,
            tpm_sha_scheme: TpmShaScheme::Ours3F,
            tpm_sha_profile: TpmShaProfile::Small,
            credential_scheme: CredentialScheme::SphincsPlus,
            risc0_segment_limit_po2: None,
        }
    }
}

impl ProtocolConfig {
    /// Selects the SPHINCS+/FAEST parameter label.
    pub fn with_params(mut self, params: impl Into<String>) -> Self {
        self.sphincs_params = normalize_param_name(&params.into());
        self.security = SecurityLevel::from_name(&self.sphincs_params);
        self.tpm_sha_profile = TpmShaProfile::from_name(&self.sphincs_params);
        self
    }

    /// Selects the RISC0 proof-system backend hash label.
    pub fn with_backend(mut self, backend: impl Into<String>) -> Self {
        self.backend_hash = backend.into();
        self
    }

    /// Selects simulated, TPM-only-real, or fully-real proof mode.
    pub fn with_proof_mode(mut self, proof_mode: ProofMode) -> Self {
        self.proof_mode = proof_mode;
        self
    }

    /// Selects the TPM primitive independently from the RISC0 receipt hash.
    pub fn with_tpm_backend(mut self, tpm_backend: TpmBackend) -> Self {
        self.tpm_backend = tpm_backend;
        self
    }

    /// Selects Ours-3F or the CDENW'23--Ours-5F SHA-2 signing relation.
    pub fn with_tpm_sha_scheme(mut self, scheme: TpmShaScheme) -> Self {
        self.tpm_sha_scheme = scheme;
        self
    }

    /// Selects SPHINCS+ or F-SPHINCS+ as the issuer credential.
    pub fn with_credential_scheme(mut self, scheme: CredentialScheme) -> Self {
        self.credential_scheme = scheme;
        self
    }

    /// Selects the TPM-SHA VOLE size/speed profile explicitly.
    pub fn with_tpm_sha_profile(mut self, profile: TpmShaProfile) -> Self {
        self.tpm_sha_profile = profile;
        self
    }

    /// Returns the public TPM token length for the selected primitive.
    pub fn tpm_token_bytes(&self) -> usize {
        match self.tpm_backend {
            TpmBackend::Aes => self.security.token_bytes(),
            TpmBackend::Sha2 => self.security.sha_digest_bytes(),
        }
    }

    /// Returns the issuer nonce length without conflating it with SHA digests.
    pub fn issuer_nonce_bytes(&self) -> usize {
        match self.tpm_backend {
            TpmBackend::Aes => self.security.token_bytes(),
            TpmBackend::Sha2 => self.security.key_bytes(),
        }
    }

    /// Selects an optional RISC0 segment limit exponent for host proofs.
    pub fn with_risc0_segment_limit_po2(mut self, segment_limit_po2: Option<u32>) -> Self {
        self.risc0_segment_limit_po2 = segment_limit_po2;
        self
    }

    /// Rejects unsupported parameter/proof combinations before running algorithms.
    fn ensure_real_supported(&self) -> DaaResult<()> {
        if self.proof_mode.uses_real_proofs() && param_spec(&self.sphincs_params).is_none() {
            return Err(DaaError::UnsupportedParameterSet);
        }
        if self.tpm_sha_scheme == TpmShaScheme::Cdenw23Ours5F
            && (self.tpm_backend != TpmBackend::Sha2
                || self.credential_scheme != CredentialScheme::FSphincsPlus)
        {
            return Err(DaaError::UnsupportedProtocolCombination);
        }
        Ok(())
    }

    /// Returns the selected DAA/SPHINCS+/FAEST parameter specification.
    fn param_spec(&self) -> DaaResult<ParamSpec> {
        param_spec(&self.sphincs_params).ok_or(DaaError::UnsupportedParameterSet)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofMode {
    Simulated,
    RealTpm,
    Real128s,
}

impl ProofMode {
    /// Parses a CLI proof-mode label.
    pub fn from_name(name: &str) -> DaaResult<Self> {
        match name {
            "simulated" => Ok(Self::Simulated),
            "real-tpm" => Ok(Self::RealTpm),
            "real" | "real-128s" => Ok(Self::Real128s),
            _ => Err(DaaError::UnsupportedProofMode),
        }
    }

    /// Returns true when the mode uses real FAEST or RISC0 proof paths.
    fn uses_real_proofs(self) -> bool {
        matches!(self, Self::RealTpm | Self::Real128s)
    }
}

#[derive(Debug, Clone, Copy)]
struct ParamSpec {
    sphincs_env: &'static str,
    lambda: u32,
    fast: bool,
}

impl ParamSpec {
    /// Returns the FAEST variant suffix used in benchmark labels.
    fn faest_suffix(self) -> &'static str {
        match (self.lambda, self.fast) {
            (128, false) => "128s",
            (128, true) => "128f",
            (192, false) => "192s",
            (192, true) => "192f",
            (256, false) => "256s",
            (256, true) => "256f",
            _ => "unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct IssuerKeypair {
    pub mpk: Bytes,
    pub msk: Bytes,
}

#[derive(Debug, Clone)]
pub struct IssuerState {
    pub group_list: Vec<GroupEntry>,
}

#[derive(Debug, Clone)]
pub struct GroupEntry {
    pub member_id: u64,
    pub et: Bytes,
    pub credential: Credential,
}

#[derive(Debug, Clone)]
pub struct RevocationState {
    pub key_rl: Vec<Bytes>,
    pub link_rl: Vec<(Bytes, Bytes)>,
}

impl RevocationState {
    /// Creates empty key and link revocation lists.
    pub fn empty() -> Self {
        Self {
            key_rl: Vec::new(),
            link_rl: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TpmState {
    pub member_id: u64,
    pub sk: Bytes,
}

#[derive(Debug, Clone)]
pub struct HostState {
    pub member_id: u64,
    pub credential: Credential,
    /// Entry token on which the issuer credential was issued during Join.
    pub credential_et: Bytes,
}

#[derive(Debug, Clone)]
pub struct Credential {
    pub sigma: Bytes,
    pub issuer_nonce: Bytes,
}

#[derive(Debug, Clone)]
pub struct ProofArtifact {
    pub kind: String,
    pub backend: String,
    pub statement_hash: Bytes,
    pub proof_bytes: Bytes,
    pub seal_bytes: Option<usize>,
}

/// Public Setup material for extracting the issuer's credential-capable seed.
#[derive(Debug, Clone)]
pub struct IssuerAnchorOutput {
    pub certificate: Bytes,
    pub public_a: Bytes,
    pub public_b: Bytes,
    pub anchor_value: Bytes,
    pub pi_i: ProofArtifact,
}

impl ProofArtifact {
    /// Returns the serialized proof size in bytes.
    pub fn size_bytes(&self) -> usize {
        self.proof_bytes.len()
    }

    /// Returns the RISC0 cryptographic seal size when available.
    pub fn seal_size_bytes(&self) -> Option<usize> {
        self.seal_bytes
    }
}

#[derive(Debug, Clone)]
pub struct DaaSignature {
    pub rho: Bytes,
    pub slt: Bytes,
    pub hk: Bytes,
    /// Public only for CDENW'23--Ours-5F; empty for Ours-3F and legacy AES.
    pub cet: Bytes,
    pub pi_tpm: ProofArtifact,
    pub pi_host: ProofArtifact,
}

#[derive(Debug, Clone)]
pub struct SetupOutput {
    pub config: ProtocolConfig,
    pub issuer_keys: IssuerKeypair,
    pub issuer_anchor: IssuerAnchorOutput,
    pub issuer_state: IssuerState,
    pub revocation_state: RevocationState,
}

#[derive(Debug, Clone)]
pub struct JoinOutput {
    pub tpm_state: TpmState,
    pub host_state: HostState,
    pub et: Bytes,
    pub pi_join: ProofArtifact,
}

#[derive(Debug, Clone)]
pub struct SignOutput {
    pub signature: DaaSignature,
    pub et: Bytes,
    pub msg_prime: Bytes,
}

#[derive(Debug, Clone)]
pub struct FullRunOutput {
    pub accepted: bool,
    pub linked_same_bsn: bool,
    pub linked_different_bsn: bool,
    pub trace: BenchmarkTrace,
    pub signature: DaaSignature,
}

#[derive(Debug, Clone)]
pub struct BenchmarkTrace {
    entries: Vec<BenchmarkEntry>,
    sizes: Vec<BenchmarkSizeEntry>,
}

impl BenchmarkTrace {
    /// Creates an empty benchmark trace.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            sizes: Vec::new(),
        }
    }

    /// Appends a duration-based benchmark entry.
    pub fn add(&mut self, name: impl Into<String>, duration: Duration) {
        self.entries.push(BenchmarkEntry {
            name: name.into(),
            micros: duration.as_micros(),
        });
    }

    /// Appends a millisecond-based benchmark entry from an external runner.
    pub fn add_millis(&mut self, name: impl Into<String>, millis: u128) {
        self.entries.push(BenchmarkEntry {
            name: name.into(),
            micros: millis * 1000,
        });
    }

    /// Appends a byte-size benchmark entry.
    pub fn add_size(&mut self, name: impl Into<String>, bytes: usize) {
        self.sizes.push(BenchmarkSizeEntry {
            name: name.into(),
            bytes,
        });
    }

    /// Measures a closure and appends its duration under the given name.
    pub fn scoped<T>(&mut self, name: impl Into<String>, f: impl FnOnce() -> T) -> T {
        let name = name.into();
        let start = Instant::now();
        let out = f();
        self.add(name, start.elapsed());
        out
    }

    /// Returns all recorded benchmark entries.
    pub fn entries(&self) -> &[BenchmarkEntry] {
        &self.entries
    }

    /// Returns all recorded size entries.
    pub fn sizes(&self) -> &[BenchmarkSizeEntry] {
        &self.sizes
    }

    /// Sums exact and nested benchmark entries for a prefix.
    pub fn total_micros(&self, prefix: &str) -> u128 {
        self.entries
            .iter()
            .filter(|entry| entry.name == prefix || entry.name.starts_with(&format!("{prefix}.")))
            .map(|entry| entry.micros)
            .sum()
    }

    /// Sums step entries added after a trace index for synthetic totals.
    fn step_sum_micros_since(&self, start: usize, prefix: &str) -> u128 {
        self.entries[start..]
            .iter()
            .filter(|entry| entry.name.starts_with(prefix) && !entry.name.ends_with(".total"))
            .map(|entry| entry.micros)
            .sum()
    }

    /// Serializes the benchmark trace to a small JSON object.
    pub fn to_json(&self) -> String {
        let mut out = String::from("{\n  \"entries\": [\n");
        for (idx, entry) in self.entries.iter().enumerate() {
            let comma = if idx + 1 == self.entries.len() {
                ""
            } else {
                ","
            };
            out.push_str(&format!(
                "    {{ \"name\": \"{}\", \"micros\": {} }}{}\n",
                json_escape(&entry.name),
                entry.micros,
                comma
            ));
        }
        out.push_str("  ],\n");
        out.push_str("  \"sizes\": [\n");
        for (idx, entry) in self.sizes.iter().enumerate() {
            let comma = if idx + 1 == self.sizes.len() { "" } else { "," };
            out.push_str(&format!(
                "    {{ \"name\": \"{}\", \"bytes\": {} }}{}\n",
                json_escape(&entry.name),
                entry.bytes,
                comma
            ));
        }
        out.push_str("  ]\n}\n");
        out
    }
}

impl Default for BenchmarkTrace {
    /// Creates the default empty benchmark trace.
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct BenchmarkEntry {
    pub name: String,
    pub micros: u128,
}

#[derive(Debug, Clone)]
pub struct BenchmarkSizeEntry {
    pub name: String,
    pub bytes: usize,
}

/// Circuit-size metadata returned by the TPM-SHA backend.
#[derive(Debug, Clone, Copy)]
pub struct TpmShaCircuitStats {
    pub private_input_bits: usize,
    pub public_input_bits: usize,
    pub output_bits: usize,
    pub and_gates: usize,
    pub xor_gates: usize,
    pub total_nodes: usize,
}

/// One warm-circuit benchmark sample for Join and joint TPM signing.
#[derive(Debug, Clone)]
pub struct TpmShaBenchmark {
    pub security: SecurityLevel,
    pub profile: TpmShaProfile,
    pub hash_name: &'static str,
    pub key_bytes: usize,
    pub digest_bytes: usize,
    pub prepare: Duration,
    pub join_prove: Duration,
    pub join_verify: Duration,
    pub join_proof_bytes: usize,
    pub join_stats: TpmShaCircuitStats,
    pub sign_prove: Duration,
    pub sign_verify: Duration,
    pub sign_proof_bytes: usize,
    pub sign_stats: TpmShaCircuitStats,
}

/// One Setup issuer-anchor benchmark sample.
#[derive(Debug, Clone)]
pub struct IssuerAnchorBenchmark {
    pub security: SecurityLevel,
    pub profile: TpmShaProfile,
    pub credential_scheme: CredentialScheme,
    pub compression_blocks: usize,
    pub keygen: Duration,
    pub anchor_generation: Duration,
    pub certificate_verify: Duration,
    pub proof_prepare: Duration,
    pub proof_prove: Duration,
    pub proof_verify: Duration,
    pub proof_bytes: usize,
    pub certificate_bytes: usize,
    pub proof_stats: TpmShaCircuitStats,
}

#[derive(Debug)]
pub enum DaaError {
    CommitmentMismatch,
    InvalidJoinProof,
    InvalidTpmProof,
    InvalidHostProof,
    RevokedKey,
    RevokedLinkToken,
    InvalidCredential,
    InvalidIssuerAnchor,
    UnsupportedParameterSet,
    UnsupportedProofMode,
    UnsupportedTpmBackend,
    UnsupportedTpmShaScheme,
    UnsupportedCredentialScheme,
    UnsupportedProtocolCombination,
    ExternalHostProof,
}

impl fmt::Display for DaaError {
    /// Formats DAA errors by their enum variant name.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for DaaError {}

pub type DaaResult<T> = Result<T, DaaError>;

/// Benchmarks prepared TPM-SHA Join and signing circuits without SPHINCS+/RISC0 work.
pub fn benchmark_tpm_sha(
    security: SecurityLevel,
    profile: TpmShaProfile,
) -> DaaResult<TpmShaBenchmark> {
    let params = match (security, profile) {
        (SecurityLevel::L128, TpmShaProfile::Small) => "sha2-128s",
        (SecurityLevel::L128, TpmShaProfile::Fast) => "sha2-128f",
        (SecurityLevel::L192, TpmShaProfile::Small) => "sha2-192s",
        (SecurityLevel::L192, TpmShaProfile::Fast) => "sha2-192f",
        (SecurityLevel::L256, TpmShaProfile::Small) => "sha2-256s",
        (SecurityLevel::L256, TpmShaProfile::Fast) => "sha2-256f",
    };
    let config = ProtocolConfig::default()
        .with_params(params)
        .with_tpm_backend(TpmBackend::Sha2)
        .with_proof_mode(ProofMode::RealTpm);

    let prepare_started = Instant::now();
    if unsafe { daa_tpm_sha_prepare(security.bits(), profile.code()) } != 0 {
        return Err(DaaError::InvalidTpmProof);
    }
    let prepare = prepare_started.elapsed();

    let key_bytes = security.key_bytes();
    let digest_bytes = security.sha_digest_bytes();
    let sk: Bytes = (0..key_bytes)
        .map(|i| (0x11u8).wrapping_add(i as u8))
        .collect();
    let s: Bytes = (0..key_bytes)
        .map(|i| (0xa1u8).wrapping_add(i as u8))
        .collect();
    let gid = group_id(&config, b"TPM-SHA benchmark issuer public key");
    let lid = link_id(&config, b"TPM-SHA benchmark basename");
    let sign_context = message_prime(&config, b"TPM-SHA benchmark message", b"fixed-rho");
    let values = tpm_sign_values(&config, &sk, &s, &sign_context, &lid, &gid);
    let (et, slt, hk) = (&values.et, &values.slt, &values.hk);
    let join_context = join_proof_message(&config, &gid, et);

    let join_started = Instant::now();
    let join_proof = prove_join_sha_real(&config, &sk, &gid, et, &join_context)?;
    let join_prove = join_started.elapsed();
    let join_verify_started = Instant::now();
    if !verify_join_sha_real(&config, &join_proof, &gid, et, &join_context) {
        return Err(DaaError::InvalidJoinProof);
    }
    let join_verify = join_verify_started.elapsed();

    let sign_started = Instant::now();
    let sign_proof = prove_tpm_sha_real(&config, &lid, &gid, &sk, &s, &sign_context, et, slt, hk)?;
    let sign_prove = sign_started.elapsed();
    let sign_verify_started = Instant::now();
    if !verify_tpm_sha_real(&config, &sign_proof, &lid, &gid, slt, hk, &sign_context) {
        return Err(DaaError::InvalidTpmProof);
    }
    let sign_verify = sign_verify_started.elapsed();

    let join_stats = tpm_sha_stats(security, profile, false)?;
    let sign_stats = tpm_sha_stats(security, profile, true)?;
    Ok(TpmShaBenchmark {
        security,
        profile,
        hash_name: sha2_name(security),
        key_bytes,
        digest_bytes,
        prepare,
        join_prove,
        join_verify,
        join_proof_bytes: join_proof.size_bytes(),
        join_stats,
        sign_prove,
        sign_verify,
        sign_proof_bytes: sign_proof.size_bytes(),
        sign_stats,
    })
}

/// Benchmarks the real deterministic issuer anchor and its VOLEith pi_I.
pub fn benchmark_issuer_anchor(config: ProtocolConfig) -> DaaResult<IssuerAnchorBenchmark> {
    config.ensure_real_supported()?;
    if !config.proof_mode.uses_real_proofs() {
        return Err(DaaError::UnsupportedProofMode);
    }
    let setup = issuer_setup_anchor_external(&config)?;
    let keygen = setup.keygen;
    let pk = setup.pk;
    let native = setup.anchor;
    let prepared = Instant::now();
    if unsafe {
        daa_issuer_anchor_prepare(
            config.security.bits(),
            config.tpm_sha_profile.code(),
            issuer_anchor_kind(&config),
        )
    } != 0
    {
        return Err(DaaError::InvalidIssuerAnchor);
    }
    let proof_prepare = prepared.elapsed();
    let context = issuer_anchor_context(&config, &pk, &native.certificate);
    let prove_started = Instant::now();
    let pi_i = prove_issuer_anchor_real(&config, &native, &context)?;
    let proof_prove = prove_started.elapsed();
    let verify_started = Instant::now();
    if !verify_issuer_anchor_real(&config, &native, &context, &pi_i) {
        return Err(DaaError::InvalidIssuerAnchor);
    }
    let proof_verify = verify_started.elapsed();
    let mut malformed_proof = pi_i.clone();
    let proof_offset = malformed_proof.proof_bytes.len() / 2;
    malformed_proof.proof_bytes[proof_offset] ^= 1;
    if verify_issuer_anchor_real(&config, &native, &context, &malformed_proof) {
        return Err(DaaError::InvalidIssuerAnchor);
    }
    let mut wrong_statement = native.clone();
    wrong_statement.anchor_value[0] ^= 1;
    if verify_issuer_anchor_real(&config, &wrong_statement, &context, &pi_i) {
        return Err(DaaError::InvalidIssuerAnchor);
    }
    let proof_stats = issuer_anchor_stats(&config)?;
    Ok(IssuerAnchorBenchmark {
        security: config.security,
        profile: config.tpm_sha_profile,
        credential_scheme: config.credential_scheme,
        compression_blocks: if config.credential_scheme == CredentialScheme::SphincsPlus {
            2
        } else {
            8
        },
        keygen,
        anchor_generation: native.generation,
        certificate_verify: native.certificate_verify,
        proof_prepare,
        proof_prove,
        proof_verify,
        proof_bytes: pi_i.size_bytes(),
        certificate_bytes: native.certificate.len(),
        proof_stats,
    })
}

/// Converts the stable C ABI statistics structure into the public Rust type.
fn tpm_sha_stats(
    security: SecurityLevel,
    profile: TpmShaProfile,
    signing: bool,
) -> DaaResult<TpmShaCircuitStats> {
    let mut raw = DaaTpmShaStats::default();
    let ret = unsafe {
        if signing {
            daa_tpm_sha_sign_stats(security.bits(), profile.code(), &mut raw)
        } else {
            daa_tpm_sha_join_stats(security.bits(), profile.code(), &mut raw)
        }
    };
    if ret != 0 {
        return Err(DaaError::InvalidTpmProof);
    }
    Ok(TpmShaCircuitStats {
        private_input_bits: raw.private_input_bits,
        public_input_bits: raw.public_input_bits,
        output_bits: raw.output_bits,
        and_gates: raw.and_gates,
        xor_gates: raw.xor_gates,
        total_nodes: raw.total_nodes,
    })
}

/// Reads the prepared issuer-anchor circuit statistics through the C ABI.
fn issuer_anchor_stats(config: &ProtocolConfig) -> DaaResult<TpmShaCircuitStats> {
    let mut raw = DaaTpmShaStats::default();
    let ret = unsafe {
        daa_issuer_anchor_stats(
            config.security.bits(),
            config.tpm_sha_profile.code(),
            issuer_anchor_kind(config),
            &mut raw,
        )
    };
    if ret != 0 {
        return Err(DaaError::InvalidIssuerAnchor);
    }
    Ok(TpmShaCircuitStats {
        private_input_bits: raw.private_input_bits,
        public_input_bits: raw.public_input_bits,
        output_bits: raw.output_bits,
        and_gates: raw.and_gates,
        xor_gates: raw.xor_gates,
        total_nodes: raw.total_nodes,
    })
}

/// Runs issuer setup and initializes the protocol state.
pub fn setup(config: ProtocolConfig, trace: &mut BenchmarkTrace) -> SetupOutput {
    let mut rng = DeterministicRng::new(config.deterministic_seed);
    if config.tpm_backend == TpmBackend::Sha2 && config.proof_mode.uses_real_proofs() {
        trace.scoped("setup.tpm_sha.prepare", || {
            let ret = unsafe {
                match config.tpm_sha_scheme {
                    TpmShaScheme::Ours3F => {
                        daa_tpm_sha_prepare(config.security.bits(), config.tpm_sha_profile.code())
                    }
                    TpmShaScheme::Cdenw23Ours5F => daa_tpm_sha_chen23_prepare(
                        config.security.bits(),
                        config.tpm_sha_profile.code(),
                    ),
                }
            };
            assert_eq!(ret, 0, "TPM_SHA circuit preparation failed");
        });
    }
    let mut external_anchor = None;
    let (mpk, msk) = match config.proof_mode {
        ProofMode::Simulated => trace.scoped("setup.total", || {
            let msk = rng.bytes(config.security.key_bytes());
            let mpk = hash_many(config.tpm_token_bytes(), &[b"issuer-mpk", &msk]);
            (mpk, msk)
        }),
        ProofMode::RealTpm | ProofMode::Real128s => {
            let issuer = issuer_setup_anchor_external(&config)
                .expect("issuer credential setup and anchor generation failed");
            trace.add("setup.total", issuer.keygen);
            external_anchor = Some(issuer.anchor);
            (issuer.pk, issuer.sk)
        }
    };
    let issuer_anchor = match config.proof_mode {
        ProofMode::Simulated => {
            let certificate = hash_many(32, &[b"issuer-anchor-certificate", &mpk]);
            let public_a = hash_many(
                if config.credential_scheme == CredentialScheme::SphincsPlus {
                    32
                } else {
                    64
                },
                &[b"issuer-anchor-public-a", &mpk],
            );
            let public_b = hash_many(
                if config.credential_scheme == CredentialScheme::SphincsPlus {
                    44
                } else {
                    64
                },
                &[b"issuer-anchor-public-b", &mpk],
            );
            let anchor_value = hash_many(
                if config.credential_scheme == CredentialScheme::SphincsPlus {
                    2 * config.security.key_bytes()
                } else {
                    64
                },
                &[&msk, &public_b],
            );
            let pi_i = trace.scoped("setup.pi_i.prove", || {
                simulated_proof(
                    "pi_i",
                    "simulated-voleith-sha256-anchor",
                    config.security.key_bytes(),
                    &[&public_a, &public_b, &anchor_value, &certificate, &mpk],
                    &[&msk],
                )
            });
            trace.scoped("setup.pi_i.verify", || {
                assert!(verify_simulated_proof(
                    &pi_i,
                    &[&public_a, &public_b, &anchor_value, &certificate, &mpk],
                    &[&msk],
                ));
            });
            IssuerAnchorOutput {
                certificate,
                public_a,
                public_b,
                anchor_value,
                pi_i,
            }
        }
        ProofMode::RealTpm | ProofMode::Real128s => {
            let native = external_anchor
                .take()
                .expect("issuer anchor material missing after real setup");
            trace.add("setup.anchor.generate", native.generation);
            trace.add("setup.anchor.certificate_verify", native.certificate_verify);
            trace.scoped("setup.pi_i.prepare", || {
                let ret = unsafe {
                    daa_issuer_anchor_prepare(
                        config.security.bits(),
                        config.tpm_sha_profile.code(),
                        issuer_anchor_kind(&config),
                    )
                };
                assert_eq!(ret, 0, "issuer anchor circuit preparation failed");
            });
            let context = issuer_anchor_context(&config, &mpk, &native.certificate);
            let pi_i = trace.scoped("setup.pi_i.prove", || {
                prove_issuer_anchor_real(&config, &native, &context)
                    .expect("issuer anchor proof failed")
            });
            trace.scoped("setup.pi_i.verify", || {
                assert!(verify_issuer_anchor_real(&config, &native, &context, &pi_i));
            });
            IssuerAnchorOutput {
                certificate: native.certificate,
                public_a: native.public_a,
                public_b: native.public_b,
                anchor_value: native.anchor_value,
                pi_i,
            }
        }
    };
    trace.add_size(
        "size.setup.issuer_anchor_certificate_bytes",
        issuer_anchor.certificate.len(),
    );
    trace.add_size(
        "size.setup.pi_i.voleith_proof_bytes",
        issuer_anchor.pi_i.size_bytes(),
    );
    SetupOutput {
        config,
        issuer_keys: IssuerKeypair { mpk, msk },
        issuer_anchor,
        issuer_state: IssuerState {
            group_list: Vec::new(),
        },
        revocation_state: RevocationState::empty(),
    }
}

/// Runs the join protocol between host, TPM, and issuer.
pub fn join(
    setup: &mut SetupOutput,
    member_id: u64,
    trace: &mut BenchmarkTrace,
) -> DaaResult<JoinOutput> {
    setup.config.ensure_real_supported()?;
    let total = Instant::now();
    let trace_start = trace.entries.len();
    let mut rng = DeterministicRng::new(setup.config.deterministic_seed ^ member_id);

    let gid_and_commit_input = trace.scoped("join.host", || {
        let gid = group_id(&setup.config, &setup.issuer_keys.mpk);
        let r = rng.bytes(setup.config.security.key_bytes());
        (gid, r)
    });
    let (gid, r) = gid_and_commit_input;

    let (sk, et) = trace.scoped("join.tpm.keygen_owf", || {
        let mut sk = rng.bytes(setup.config.security.key_bytes());
        if setup.config.tpm_backend == TpmBackend::Aes {
            normalize_faest_key(&mut sk);
        }
        let et = tpm_et(&setup.config, &sk, &gid);
        (sk, et)
    });
    let join_msg = join_proof_message(&setup.config, &gid, &et);

    let pi_join = trace.scoped("join.tpm.pi_join_prove", || match setup.config.proof_mode {
        ProofMode::Simulated => Ok(simulated_proof(
            "pi_join",
            match setup.config.tpm_backend {
                TpmBackend::Aes => "simulated-faest-join",
                TpmBackend::Sha2 => "simulated-voleith-sha2-join",
            },
            setup.config.tpm_token_bytes(),
            &[&gid, &et],
            &[&sk],
        )),
        ProofMode::RealTpm | ProofMode::Real128s => {
            prove_join_real(&setup.config, &sk, &gid, &et, &join_msg)
        }
    })?;

    let com = join_commitment(&setup.config, &et, &r);
    trace.scoped("join.issuer.commit_check", || {
        let expected = join_commitment(&setup.config, &et, &r);
        if expected != com {
            return Err(DaaError::CommitmentMismatch);
        }
        Ok(())
    })?;

    trace.scoped("join.issuer.pi_join_verify", || {
        let ok = match setup.config.proof_mode {
            ProofMode::Simulated => verify_simulated_proof(&pi_join, &[&gid, &et], &[&sk]),
            ProofMode::RealTpm | ProofMode::Real128s => {
                verify_join_real(&setup.config, &pi_join, &gid, &et, &join_msg)
            }
        };
        if !ok {
            return Err(DaaError::InvalidJoinProof);
        }
        Ok(())
    })?;

    let issuer_nonce = rng.bytes(setup.config.issuer_nonce_bytes());
    let cred_msg = credential_message(&et, &issuer_nonce);
    let credential = match setup.config.proof_mode {
        ProofMode::Simulated => trace.scoped("join.issuer.credential_sign", || Credential {
            sigma: issuer_sign_simulated(&setup.issuer_keys, &cred_msg),
            issuer_nonce,
        }),
        ProofMode::RealTpm | ProofMode::Real128s => {
            let signed = issuer_sign_external(&setup.config, &setup.issuer_keys.msk, &cred_msg)?;
            trace.add_millis("join.issuer.credential_sign", signed.sign_millis);
            Credential {
                sigma: signed.signature,
                issuer_nonce,
            }
        }
    };

    setup.issuer_state.group_list.push(GroupEntry {
        member_id,
        et: et.clone(),
        credential: credential.clone(),
    });

    if setup.config.proof_mode.uses_real_proofs() {
        trace.add(
            "join.total",
            Duration::from_micros(trace.step_sum_micros_since(trace_start, "join.") as u64),
        );
    } else {
        trace.add("join.total", total.elapsed());
    }

    Ok(JoinOutput {
        tpm_state: TpmState { member_id, sk },
        host_state: HostState {
            member_id,
            credential,
            credential_et: et.clone(),
        },
        et,
        pi_join,
    })
}

/// Runs a full DAA signing operation with TPM and host proofs.
pub fn sign(
    setup: &SetupOutput,
    tpm: &TpmState,
    host: &HostState,
    msg: &[u8],
    bsn: &[u8],
    trace: &mut BenchmarkTrace,
) -> DaaResult<SignOutput> {
    setup.config.ensure_real_supported()?;
    sign_internal(setup, tpm, host, msg, bsn, trace, true)
}

/// Runs signing with optional host proving for internal link-test signatures.
fn sign_internal(
    setup: &SetupOutput,
    tpm: &TpmState,
    host: &HostState,
    msg: &[u8],
    bsn: &[u8],
    trace: &mut BenchmarkTrace,
    prove_host: bool,
) -> DaaResult<SignOutput> {
    let total = Instant::now();
    let trace_start = trace.entries.len();
    let mut rng = DeterministicRng::new(
        setup.config.deterministic_seed ^ tpm.member_id ^ stable_u64(msg) ^ stable_u64(bsn),
    );

    let host_precompute_start = Instant::now();
    let (gid, lid) = {
        let gid = group_id(&setup.config, &setup.issuer_keys.mpk);
        let lid = link_id(&setup.config, bsn);
        (gid, lid)
    };
    let mut host_precompute_elapsed = host_precompute_start.elapsed();

    let rho = rng.bytes(setup.config.security.key_bytes());
    let tpm_msg_prime = message_prime(&setup.config, msg, &rho);
    let mut s = rng.bytes(setup.config.security.key_bytes());
    if setup.config.tpm_backend == TpmBackend::Aes {
        normalize_faest_key(&mut s);
    }

    let primitive_step = match (setup.config.tpm_backend, setup.config.tpm_sha_scheme) {
        (TpmBackend::Aes, _) => "sign.tpm.3aes",
        (TpmBackend::Sha2, TpmShaScheme::Ours3F) => "sign.tpm.3sha2",
        (TpmBackend::Sha2, TpmShaScheme::Cdenw23Ours5F) => "sign.tpm.5sha2",
    };
    let values = trace.scoped(primitive_step, || {
        tpm_sign_values(&setup.config, &tpm.sk, &s, &tpm_msg_prime, &lid, &gid)
    });
    let et = &values.et;
    let slt = &values.slt;
    let hk = &values.hk;
    let cet = &values.cet;
    if et != &host.credential_et {
        return Err(DaaError::InvalidCredential);
    }

    let pi_tpm = trace.scoped("sign.tpm.pi_tpm_prove", || match setup.config.proof_mode {
        ProofMode::Simulated => Ok(simulated_proof(
            "pi_tpm",
            match setup.config.tpm_backend {
                TpmBackend::Aes => "simulated-faest-3aes",
                TpmBackend::Sha2 if setup.config.tpm_sha_scheme == TpmShaScheme::Ours3F => {
                    "simulated-voleith-3sha2"
                }
                TpmBackend::Sha2 => "simulated-voleith-5sha2",
            },
            setup.config.tpm_token_bytes() * 3,
            &[&lid, &gid, slt, hk, cet, &tpm_msg_prime],
            &[&tpm.sk, &s, et, &values.hook_secret],
        )),
        ProofMode::RealTpm | ProofMode::Real128s => prove_tpm_real(
            &setup.config,
            &lid,
            &gid,
            &tpm.sk,
            &values.hook_secret,
            &tpm_msg_prime,
            et,
            slt,
            hk,
            cet,
        ),
    })?;

    let host_precompute_start = Instant::now();
    let msg_prime = message_prime(&setup.config, msg, &rho);
    let (host_hk, host_cet) = host_hook_outputs(&setup.config, &values.hook_secret, et);
    host_precompute_elapsed += host_precompute_start.elapsed();
    trace.add("sign.host.precompute", host_precompute_elapsed);

    let pi_host = {
        let credential_ok = match setup.config.proof_mode {
            ProofMode::Simulated => {
                let cred_msg = credential_message(&et, &host.credential.issuer_nonce);
                issuer_verify_simulated(&setup.issuer_keys, &cred_msg, &host.credential.sigma)
            }
            ProofMode::RealTpm | ProofMode::Real128s => true,
        };
        let witness_ok = host_hk == *hk && host_cet == *cet && credential_ok;
        match (setup.config.proof_mode, prove_host) {
            (ProofMode::Simulated, _) | (ProofMode::RealTpm, _) | (_, false) => {
                trace.scoped("sign.host.pi_host_prove", || {
                    Ok(simulated_proof(
                        "pi_host",
                        &format!("simulated-risc0-{}", setup.config.backend_hash),
                        setup.config.tpm_token_bytes() * 4,
                        &[hk, cet, &setup.issuer_keys.mpk],
                        &[
                            et,
                            &values.hook_secret,
                            &host.credential.sigma,
                            &bool_byte(witness_ok),
                        ],
                    ))
                })
            }
            (ProofMode::Real128s, true) => {
                if !witness_ok {
                    return Err(DaaError::InvalidCredential);
                }
                let host_proof = prove_host_risc0_128s(
                    &setup.config,
                    &setup.issuer_keys.mpk,
                    &host.credential.sigma,
                    hk,
                    cet,
                    &values.hook_secret,
                    et,
                    &host.credential.issuer_nonce,
                )?;
                trace.add_millis("sign.host.pi_host_prove", host_proof.prover_millis);
                Ok(ProofArtifact {
                    kind: "pi_host".to_string(),
                    backend: format!(
                        "risc0-{}-{}",
                        setup.config.backend_hash, setup.config.sphincs_params
                    ),
                    statement_hash: hash_many(32, &[hk, cet, &setup.issuer_keys.mpk]),
                    proof_bytes: host_proof.proof_bytes,
                    seal_bytes: host_proof.seal_bytes,
                })
            }
        }
    }?;

    if setup.config.proof_mode == ProofMode::Real128s {
        trace.add(
            "sign.total",
            Duration::from_micros(trace.step_sum_micros_since(trace_start, "sign.") as u64),
        );
    } else {
        trace.add("sign.total", total.elapsed());
    }

    Ok(SignOutput {
        signature: DaaSignature {
            rho,
            slt: slt.clone(),
            hk: hk.clone(),
            cet: cet.clone(),
            pi_tpm,
            pi_host,
        },
        et: et.clone(),
        msg_prime,
    })
}

/// Verifies a DAA signature against revocation state and both proofs.
pub fn verify(
    setup: &SetupOutput,
    revocation: &RevocationState,
    msg: &[u8],
    bsn: &[u8],
    signature: &DaaSignature,
    trace: &mut BenchmarkTrace,
) -> DaaResult<bool> {
    setup.config.ensure_real_supported()?;
    let total = Instant::now();
    let trace_start = trace.entries.len();
    trace.scoped("verify.revocation_check", || {
        if revocation
            .link_rl
            .iter()
            .any(|(rev_bsn, rev_slt)| rev_bsn == bsn && rev_slt == &signature.slt)
        {
            return Err(DaaError::RevokedLinkToken);
        }
        if !revocation.key_rl.is_empty() {
            return Err(DaaError::RevokedKey);
        }
        Ok(())
    })?;

    let gid = group_id(&setup.config, &setup.issuer_keys.mpk);
    let lid = link_id(&setup.config, bsn);
    let msg_prime = message_prime(&setup.config, msg, &signature.rho);

    trace.scoped("verify.pi_tpm_verify", || {
        let ok = match setup.config.proof_mode {
            ProofMode::Simulated => verify_statement_only(
                &signature.pi_tpm,
                &[
                    &lid,
                    &gid,
                    &signature.slt,
                    &signature.hk,
                    &signature.cet,
                    &msg_prime,
                ],
            ),
            ProofMode::RealTpm | ProofMode::Real128s => verify_tpm_real(
                &setup.config,
                &signature.pi_tpm,
                &lid,
                &gid,
                &signature.slt,
                &signature.hk,
                &signature.cet,
                &msg_prime,
            ),
        };
        if !ok {
            return Err(DaaError::InvalidTpmProof);
        }
        Ok(())
    })?;

    match setup.config.proof_mode {
        ProofMode::Simulated | ProofMode::RealTpm => {
            trace.scoped("verify.pi_host_verify", || {
                let ok = verify_statement_only(
                    &signature.pi_host,
                    &[&signature.hk, &signature.cet, &setup.issuer_keys.mpk],
                );
                if !ok {
                    return Err(DaaError::InvalidHostProof);
                }
                Ok(())
            })?;
        }
        ProofMode::Real128s => {
            let verification = verify_host_risc0_128s(
                &setup.config,
                &signature.pi_host,
                &setup.issuer_keys.mpk,
                &signature.hk,
                &signature.cet,
            )?;
            trace.add_millis("verify.pi_host_verify", verification.verifier_millis);
            if !verification.accepted {
                return Err(DaaError::InvalidHostProof);
            }
        }
    }

    if setup.config.proof_mode == ProofMode::Real128s {
        trace.add(
            "verify.total",
            Duration::from_micros(trace.step_sum_micros_since(trace_start, "verify.") as u64),
        );
    } else {
        trace.add("verify.total", total.elapsed());
    }
    Ok(true)
}

/// Links two signatures by comparing their basename-specific link tokens.
pub fn link(
    signature_a: &DaaSignature,
    signature_b: &DaaSignature,
    trace: &mut BenchmarkTrace,
) -> bool {
    let total = Instant::now();
    let linked = trace.scoped("link.slt_compare", || signature_a.slt == signature_b.slt);
    trace.add("link.total", total.elapsed());
    linked
}

/// Returns an empty revocation state while recording the update step.
pub fn revoke_empty(trace: &mut BenchmarkTrace) -> RevocationState {
    let total = Instant::now();
    let state = trace.scoped("revoke.update_state", RevocationState::empty);
    trace.add("revoke.total", total.elapsed());
    state
}

/// Runs setup, join, sign, verify, link, and empty revocation once.
pub fn run_full(config: ProtocolConfig) -> DaaResult<FullRunOutput> {
    let mut trace = BenchmarkTrace::new();
    let mut setup_out = setup(config, &mut trace);
    let join_out = join(&mut setup_out, 1, &mut trace)?;

    let msg1 = b"DAA message one";
    let msg2 = b"DAA message two";
    let bsn = b"verifier.example/basename";
    let other_bsn = b"verifier.example/other-basename";

    let sig1 = sign(
        &setup_out,
        &join_out.tpm_state,
        &join_out.host_state,
        msg1,
        bsn,
        &mut trace,
    )?;
    let sig2 = sign_internal(
        &setup_out,
        &join_out.tpm_state,
        &join_out.host_state,
        msg2,
        bsn,
        &mut BenchmarkTrace::new(),
        false,
    )?;
    let sig3 = sign_internal(
        &setup_out,
        &join_out.tpm_state,
        &join_out.host_state,
        msg2,
        other_bsn,
        &mut BenchmarkTrace::new(),
        false,
    )?;

    record_size_metrics(&mut trace, &join_out, &sig1);

    let revocation = revoke_empty(&mut trace);
    let accepted = verify(
        &setup_out,
        &revocation,
        msg1,
        bsn,
        &sig1.signature,
        &mut trace,
    )?;
    let linked_same_bsn = link(&sig1.signature, &sig2.signature, &mut trace);
    let linked_different_bsn = link(&sig1.signature, &sig3.signature, &mut trace);

    Ok(FullRunOutput {
        accepted,
        linked_same_bsn,
        linked_different_bsn,
        trace,
        signature: sig1.signature,
    })
}

/// Records proof, credential, and signature sizes for benchmark output.
fn record_size_metrics(trace: &mut BenchmarkTrace, join: &JoinOutput, sign: &SignOutput) {
    let credential_sigma = join.host_state.credential.sigma.len();
    let credential_nonce = join.host_state.credential.issuer_nonce.len();
    let signature_remaining = sign.signature.rho.len()
        + sign.signature.slt.len()
        + sign.signature.hk.len()
        + sign.signature.cet.len();
    let signature_total = signature_remaining
        + sign.signature.pi_tpm.size_bytes()
        + sign.signature.pi_host.size_bytes();

    let join_size_name = if join.pi_join.backend.contains("voleith-") {
        "size.pi_join.voleith_proof_bytes"
    } else {
        "size.pi_join.faest_signature_bytes"
    };
    trace.add_size(join_size_name, join.pi_join.size_bytes());
    trace.add_size("size.issuer_credential.sigma", credential_sigma);
    trace.add_size("size.issuer_credential.issuer_nonce", credential_nonce);
    trace.add_size(
        "size.issuer_credential.total",
        credential_sigma + credential_nonce,
    );
    let tpm_size_name = if sign.signature.pi_tpm.backend.contains("voleith-") {
        "size.signature.pi_tpm.voleith_proof_bytes"
    } else {
        "size.signature.pi_tpm.faest_signature_bytes"
    };
    trace.add_size(tpm_size_name, sign.signature.pi_tpm.size_bytes());
    trace.add_size(
        "size.signature.pi_host.serialized_receipt_bytes",
        sign.signature.pi_host.size_bytes(),
    );
    if let Some(seal_bytes) = sign.signature.pi_host.seal_size_bytes() {
        trace.add_size("size.signature.pi_host.seal_bytes", seal_bytes);
        trace.add_size(
            "size.signature.pi_host.receipt_overhead_bytes",
            sign.signature
                .pi_host
                .size_bytes()
                .saturating_sub(seal_bytes),
        );
    }
    trace.add_size("size.signature.remaining", signature_remaining);
    trace.add_size("size.signature.total", signature_total);
}

/// Derives the group identifier from the issuer public key.
pub fn group_id(config: &ProtocolConfig, mpk: &[u8]) -> Bytes {
    match config.tpm_backend {
        TpmBackend::Aes => hash_many(16, &[b"gid", mpk, config.sphincs_params.as_bytes()]),
        TpmBackend::Sha2 => sha2_hash(
            config.security,
            &[b"DAA-GID-v1", mpk, config.sphincs_params.as_bytes()],
        ),
    }
}

/// Derives the basename-specific link identifier.
pub fn link_id(config: &ProtocolConfig, bsn: &[u8]) -> Bytes {
    match config.tpm_backend {
        TpmBackend::Aes => hash_many(16, &[b"lid", bsn, config.sphincs_params.as_bytes()]),
        TpmBackend::Sha2 => sha2_hash(
            config.security,
            &[b"DAA-LID-v1", bsn, config.sphincs_params.as_bytes()],
        ),
    }
}

/// Derives the randomized message bound to TPM proofs.
pub fn message_prime(config: &ProtocolConfig, msg: &[u8], rho: &[u8]) -> Bytes {
    match config.tpm_backend {
        TpmBackend::Aes => hash_many(config.security.key_bytes(), &[b"msg-prime", msg, rho]),
        TpmBackend::Sha2 => sha2_hash(config.security, &[b"DAA-MSG-PRIME-v1", msg, rho]),
    }
}

/// Builds the issuer credential message as et || issuer_nonce.
pub fn credential_message(et: &[u8], issuer_nonce: &[u8]) -> Bytes {
    let mut out = Vec::with_capacity(et.len() + issuer_nonce.len());
    out.extend_from_slice(et);
    out.extend_from_slice(issuer_nonce);
    out
}

/// Normalizes accepted CLI parameter names to the short DAA label.
fn normalize_param_name(name: &str) -> String {
    name.strip_prefix("sphincs-").unwrap_or(name).to_string()
}

/// Maps a short DAA parameter label to SPHINCS+ and FAEST settings.
fn param_spec(name: &str) -> Option<ParamSpec> {
    match normalize_param_name(name).as_str() {
        "sha2-128s" => Some(ParamSpec {
            sphincs_env: "sphincs-sha2-128s",
            lambda: 128,
            fast: false,
        }),
        "sha2-128f" => Some(ParamSpec {
            sphincs_env: "sphincs-sha2-128f",
            lambda: 128,
            fast: true,
        }),
        "sha2-192s" => Some(ParamSpec {
            sphincs_env: "sphincs-sha2-192s",
            lambda: 192,
            fast: false,
        }),
        "sha2-192f" => Some(ParamSpec {
            sphincs_env: "sphincs-sha2-192f",
            lambda: 192,
            fast: true,
        }),
        "sha2-256s" => Some(ParamSpec {
            sphincs_env: "sphincs-sha2-256s",
            lambda: 256,
            fast: false,
        }),
        "sha2-256f" => Some(ParamSpec {
            sphincs_env: "sphincs-sha2-256f",
            lambda: 256,
            fast: true,
        }),
        _ => None,
    }
}

/// Signs an issuer credential with the deterministic simulated signer.
fn issuer_sign_simulated(keys: &IssuerKeypair, msg: &[u8]) -> Bytes {
    hash_many(64, &[b"issuer-sig", &keys.msk, &keys.mpk, msg])
}

/// Verifies an issuer credential with the deterministic simulated signer.
fn issuer_verify_simulated(keys: &IssuerKeypair, msg: &[u8], sig: &[u8]) -> bool {
    issuer_sign_simulated(keys, msg) == sig
}

/// Computes the TPM entry token for the selected primitive.
fn tpm_et(config: &ProtocolConfig, sk: &[u8], gid: &[u8]) -> Bytes {
    match config.tpm_backend {
        TpmBackend::Aes => aes_prf(config, sk, gid),
        TpmBackend::Sha2 => sha2_hash(config.security, &[&[0x02], sk, gid]),
    }
}

/// Values shared by the TPM proof, issuer credential, and RISC0 host proof.
struct TpmSignValues {
    et: Bytes,
    slt: Bytes,
    hk: Bytes,
    cet: Bytes,
    /// `s` for Ours-3F and `sst` for CDENW'23--Ours-5F.
    hook_secret: Bytes,
}

/// Computes the TPM signing outputs while keeping et and hook secrets private.
fn tpm_sign_values(
    config: &ProtocolConfig,
    sk: &[u8],
    s: &[u8],
    sid: &[u8],
    lid: &[u8],
    gid: &[u8],
) -> TpmSignValues {
    match config.tpm_backend {
        TpmBackend::Aes => {
            let et = aes_prf(config, sk, gid);
            let slt = aes_prf(config, sk, lid);
            let hk = aes_hook(config, s, &et);
            TpmSignValues {
                et,
                slt,
                hk,
                cet: Vec::new(),
                hook_secret: s.to_vec(),
            }
        }
        TpmBackend::Sha2 if config.tpm_sha_scheme == TpmShaScheme::Ours3F => {
            let et = sha2_hash(config.security, &[&[0x02], sk, gid]);
            let slt = sha2_hash(config.security, &[&[0x01], sk, lid]);
            let hk = sha2_hash(config.security, &[&[0x03], s, &et]);
            TpmSignValues {
                et,
                slt,
                hk,
                cet: Vec::new(),
                hook_secret: s.to_vec(),
            }
        }
        TpmBackend::Sha2 => {
            let slt = sha2_hash(config.security, &[&[0x01], sk, lid]);
            let sst = sha2_hash(config.security, &[&[0x04], sk, sid]);
            let et = sha2_hash(config.security, &[&[0x02], sk, gid]);
            let hk = sha2_hash(config.security, &[&[0x05], &sst]);
            let cet = sha2_hash(config.security, &[&[0x06], &sst, &et]);
            TpmSignValues {
                et,
                slt,
                hk,
                cet,
                hook_secret: sst,
            }
        }
    }
}

/// Computes the host-side hook for the selected primitive.
fn tpm_hk(config: &ProtocolConfig, s: &[u8], et: &[u8]) -> Bytes {
    match config.tpm_backend {
        TpmBackend::Aes => aes_hook(config, s, et),
        TpmBackend::Sha2 => sha2_hash(config.security, &[&[0x03], s, et]),
    }
}

/// Recomputes exactly the public hook outputs checked by the host guest.
fn host_hook_outputs(config: &ProtocolConfig, hook_secret: &[u8], et: &[u8]) -> (Bytes, Bytes) {
    if config.tpm_backend == TpmBackend::Sha2
        && config.tpm_sha_scheme == TpmShaScheme::Cdenw23Ours5F
    {
        (
            sha2_hash(config.security, &[&[0x05], hook_secret]),
            sha2_hash(config.security, &[&[0x06], hook_secret, et]),
        )
    } else {
        (tpm_hk(config, hook_secret, et), Vec::new())
    }
}

/// Hashes a fixed-format transcript with the SHA-2 member of the security level.
fn sha2_hash(level: SecurityLevel, parts: &[&[u8]]) -> Bytes {
    match level {
        SecurityLevel::L128 => {
            let mut h = Sha256::new();
            for part in parts {
                h.update(part);
            }
            h.finalize().to_vec()
        }
        SecurityLevel::L192 => {
            let mut h = Sha384::new();
            for part in parts {
                h.update(part);
            }
            h.finalize().to_vec()
        }
        SecurityLevel::L256 => {
            let mut h = Sha512::new();
            for part in parts {
                h.update(part);
            }
            h.finalize().to_vec()
        }
    }
}

/// Evaluates the TPM AES PRF or its simulated replacement.
fn aes_prf(config: &ProtocolConfig, key: &[u8], input: &[u8]) -> Bytes {
    if config.proof_mode.uses_real_proofs() {
        return aes_owf_real(config, key, input);
    }
    hash_many(config.security.token_bytes(), &[b"aes-prf", key, input])
}

/// Evaluates the host AES hook or its simulated replacement.
fn aes_hook(config: &ProtocolConfig, s: &[u8], et: &[u8]) -> Bytes {
    if config.proof_mode.uses_real_proofs() {
        return aes_hook_real(config, s, et);
    }
    let mut out = Vec::with_capacity(config.security.token_bytes());
    let mut block_index = 0u64;
    while out.len() < config.security.token_bytes() {
        let block = hash_many(16, &[b"aes-hook", s, et, &block_index.to_le_bytes()]);
        out.extend_from_slice(&block);
        block_index += 1;
    }
    out.truncate(config.security.token_bytes());
    out
}

/// Builds the message bound to the join FAEST proof.
fn join_proof_message(config: &ProtocolConfig, gid: &[u8], et: &[u8]) -> Bytes {
    match config.tpm_backend {
        TpmBackend::Aes => hash_many(32, &[b"daa-join-faest", gid, et]),
        TpmBackend::Sha2 => sha2_hash(config.security, &[b"DAA-JOIN-VOLEITH-v1", gid, et]),
    }
}

/// Computes the Join commitment while preserving the legacy AES transcript exactly.
fn join_commitment(config: &ProtocolConfig, et: &[u8], r: &[u8]) -> Bytes {
    match config.tpm_backend {
        TpmBackend::Aes => hash_many(config.security.key_bytes(), &[b"join-com", et, r]),
        TpmBackend::Sha2 => sha2_hash(config.security, &[b"DAA-JOIN-COM-v1", et, r]),
    }
}

/// Clears the first witness bit to satisfy FAEST key restrictions.
fn normalize_faest_key(key: &mut [u8]) {
    if let Some(first) = key.first_mut() {
        *first &= !1;
    }
}

/// Computes the real TPM AES OWF through the C implementation.
fn aes_owf_real(config: &ProtocolConfig, key: &[u8], input: &[u8]) -> Bytes {
    let spec = config.param_spec().expect("supported real parameter set");
    let mut out = vec![0u8; config.security.token_bytes()];
    unsafe { daa_aes_owf(spec.lambda, key.as_ptr(), input.as_ptr(), out.as_mut_ptr()) };
    out
}

/// Computes the real TPM AES hook through the C implementation.
fn aes_hook_real(config: &ProtocolConfig, s: &[u8], et: &[u8]) -> Bytes {
    let spec = config.param_spec().expect("supported real parameter set");
    let mut out = vec![0u8; config.security.token_bytes()];
    unsafe { daa_aes_hook(spec.lambda, s.as_ptr(), et.as_ptr(), out.as_mut_ptr()) };
    out
}

/// Produces a real Join proof with the selected TPM backend.
fn prove_join_real(
    config: &ProtocolConfig,
    sk: &[u8],
    gid: &[u8],
    et: &[u8],
    msg: &[u8],
) -> DaaResult<ProofArtifact> {
    match config.tpm_backend {
        TpmBackend::Aes => prove_join_aes_real(config, sk, gid, et, msg),
        TpmBackend::Sha2 => prove_join_sha_real(config, sk, gid, et, msg),
    }
}

/// Verifies a real Join proof with the selected TPM backend.
fn verify_join_real(
    config: &ProtocolConfig,
    proof: &ProofArtifact,
    gid: &[u8],
    et: &[u8],
    msg: &[u8],
) -> bool {
    match config.tpm_backend {
        TpmBackend::Aes => verify_join_aes_real(config, proof, gid, et, msg),
        TpmBackend::Sha2 => verify_join_sha_real(config, proof, gid, et, msg),
    }
}

/// Produces a real TPM signing proof with the selected backend.
#[allow(clippy::too_many_arguments)]
fn prove_tpm_real(
    config: &ProtocolConfig,
    lid: &[u8],
    gid: &[u8],
    sk: &[u8],
    hook_secret: &[u8],
    msg_prime: &[u8],
    expected_et: &[u8],
    expected_slt: &[u8],
    expected_hk: &[u8],
    expected_cet: &[u8],
) -> DaaResult<ProofArtifact> {
    match config.tpm_backend {
        TpmBackend::Aes => prove_tpm_aes_real(
            config,
            lid,
            gid,
            sk,
            hook_secret,
            msg_prime,
            expected_et,
            expected_slt,
            expected_hk,
        ),
        TpmBackend::Sha2 if config.tpm_sha_scheme == TpmShaScheme::Ours3F => prove_tpm_sha_real(
            config,
            lid,
            gid,
            sk,
            hook_secret,
            msg_prime,
            expected_et,
            expected_slt,
            expected_hk,
        ),
        TpmBackend::Sha2 => prove_tpm_sha_chen23_real(
            config,
            lid,
            gid,
            sk,
            msg_prime,
            hook_secret,
            expected_et,
            expected_slt,
            expected_hk,
            expected_cet,
        ),
    }
}

/// Verifies a real TPM signing proof with the selected backend.
fn verify_tpm_real(
    config: &ProtocolConfig,
    proof: &ProofArtifact,
    lid: &[u8],
    gid: &[u8],
    slt: &[u8],
    hk: &[u8],
    cet: &[u8],
    msg_prime: &[u8],
) -> bool {
    match config.tpm_backend {
        TpmBackend::Aes => verify_tpm_aes_real(config, proof, lid, gid, slt, hk, msg_prime),
        TpmBackend::Sha2 if config.tpm_sha_scheme == TpmShaScheme::Ours3F => {
            verify_tpm_sha_real(config, proof, lid, gid, slt, hk, msg_prime)
        }
        TpmBackend::Sha2 => {
            verify_tpm_sha_chen23_real(config, proof, lid, gid, slt, hk, cet, msg_prime)
        }
    }
}

/// Returns the SHA-2 name used in proof backend labels.
fn sha2_name(level: SecurityLevel) -> &'static str {
    match level {
        SecurityLevel::L128 => "sha256",
        SecurityLevel::L192 => "sha384",
        SecurityLevel::L256 => "sha512",
    }
}

/// Fills the prover's explicit 256-bit randomness buffer.
fn fresh_prover_randomness() -> DaaResult<[u8; 32]> {
    let mut randomness = [0u8; 32];
    getrandom::getrandom(&mut randomness).map_err(|_| DaaError::InvalidTpmProof)?;
    Ok(randomness)
}

/// Produces the joint VOLEith proof et = H(02 || sk || gid).
fn prove_join_sha_real(
    config: &ProtocolConfig,
    sk: &[u8],
    gid: &[u8],
    et: &[u8],
    context: &[u8],
) -> DaaResult<ProofArtifact> {
    let level = config.security.bits();
    let profile = config.tpm_sha_profile.code();
    let proof_cap = unsafe { daa_tpm_sha_join_proof_bytes(level, profile) };
    if proof_cap == 0 {
        return Err(DaaError::InvalidJoinProof);
    }
    let randomness = fresh_prover_randomness().map_err(|_| DaaError::InvalidJoinProof)?;
    let mut proof = vec![0u8; proof_cap];
    let mut proof_len = proof.len();
    let ret = unsafe {
        daa_tpm_sha_join_prove(
            level,
            profile,
            sk.as_ptr(),
            sk.len(),
            gid.as_ptr(),
            gid.len(),
            et.as_ptr(),
            et.len(),
            context.as_ptr(),
            context.len(),
            randomness.as_ptr(),
            randomness.len(),
            proof.as_mut_ptr(),
            &mut proof_len,
        )
    };
    if ret != 0 || proof_len > proof.len() {
        return Err(DaaError::InvalidJoinProof);
    }
    proof.truncate(proof_len);
    Ok(ProofArtifact {
        kind: "pi_join".to_string(),
        backend: format!(
            "voleith-{}{}-join",
            sha2_name(config.security),
            config.tpm_sha_profile.name()
        ),
        statement_hash: sha2_hash(SecurityLevel::L128, &[gid, et, context]),
        proof_bytes: proof,
        seal_bytes: None,
    })
}

/// Verifies the public Join relation without receiving sk.
fn verify_join_sha_real(
    config: &ProtocolConfig,
    proof: &ProofArtifact,
    gid: &[u8],
    et: &[u8],
    context: &[u8],
) -> bool {
    unsafe {
        daa_tpm_sha_join_verify(
            config.security.bits(),
            config.tpm_sha_profile.code(),
            gid.as_ptr(),
            gid.len(),
            et.as_ptr(),
            et.len(),
            context.as_ptr(),
            context.len(),
            proof.proof_bytes.as_ptr(),
            proof.proof_bytes.len(),
        ) == 0
    }
}

/// Produces one joint proof of the three domain-separated SHA relations.
#[allow(clippy::too_many_arguments)]
fn prove_tpm_sha_real(
    config: &ProtocolConfig,
    lid: &[u8],
    gid: &[u8],
    sk: &[u8],
    s: &[u8],
    context: &[u8],
    expected_et: &[u8],
    slt: &[u8],
    hk: &[u8],
) -> DaaResult<ProofArtifact> {
    if tpm_et(config, sk, gid) != expected_et {
        return Err(DaaError::InvalidTpmProof);
    }
    let level = config.security.bits();
    let profile = config.tpm_sha_profile.code();
    let proof_cap = unsafe { daa_tpm_sha_sign_proof_bytes(level, profile) };
    if proof_cap == 0 {
        return Err(DaaError::InvalidTpmProof);
    }
    let randomness = fresh_prover_randomness()?;
    let mut proof = vec![0u8; proof_cap];
    let mut proof_len = proof.len();
    let ret = unsafe {
        daa_tpm_sha_sign_prove(
            level,
            profile,
            sk.as_ptr(),
            sk.len(),
            s.as_ptr(),
            s.len(),
            lid.as_ptr(),
            lid.len(),
            gid.as_ptr(),
            gid.len(),
            slt.as_ptr(),
            slt.len(),
            hk.as_ptr(),
            hk.len(),
            context.as_ptr(),
            context.len(),
            randomness.as_ptr(),
            randomness.len(),
            proof.as_mut_ptr(),
            &mut proof_len,
        )
    };
    if ret != 0 || proof_len > proof.len() {
        return Err(DaaError::InvalidTpmProof);
    }
    proof.truncate(proof_len);
    Ok(ProofArtifact {
        kind: "pi_tpm".to_string(),
        backend: format!(
            "voleith-{}{}-3sha2",
            sha2_name(config.security),
            config.tpm_sha_profile.name()
        ),
        statement_hash: sha2_hash(SecurityLevel::L128, &[lid, gid, slt, hk, context]),
        proof_bytes: proof,
        seal_bytes: None,
    })
}

/// Verifies the joint three-SHA public statement.
fn verify_tpm_sha_real(
    config: &ProtocolConfig,
    proof: &ProofArtifact,
    lid: &[u8],
    gid: &[u8],
    slt: &[u8],
    hk: &[u8],
    context: &[u8],
) -> bool {
    unsafe {
        daa_tpm_sha_sign_verify(
            config.security.bits(),
            config.tpm_sha_profile.code(),
            lid.as_ptr(),
            lid.len(),
            gid.as_ptr(),
            gid.len(),
            slt.as_ptr(),
            slt.len(),
            hk.as_ptr(),
            hk.len(),
            context.as_ptr(),
            context.len(),
            proof.proof_bytes.as_ptr(),
            proof.proof_bytes.len(),
        ) == 0
    }
}

/// Produces the CDENW'23--Ours-5F proof and checks all shared values first.
#[allow(clippy::too_many_arguments)]
fn prove_tpm_sha_chen23_real(
    config: &ProtocolConfig,
    lid: &[u8],
    gid: &[u8],
    sk: &[u8],
    sid: &[u8],
    expected_sst: &[u8],
    expected_et: &[u8],
    expected_slt: &[u8],
    expected_hk: &[u8],
    expected_cet: &[u8],
) -> DaaResult<ProofArtifact> {
    let digest_len = config.security.sha_digest_bytes();
    let mut slt = vec![0u8; digest_len];
    let mut sst = vec![0u8; digest_len];
    let mut et = vec![0u8; digest_len];
    let mut hk = vec![0u8; digest_len];
    let mut cet = vec![0u8; digest_len];
    let evaluated = unsafe {
        daa_tpm_sha_chen23_evaluate_sign(
            config.security.bits(),
            sk.as_ptr(),
            sk.len(),
            sid.as_ptr(),
            sid.len(),
            gid.as_ptr(),
            gid.len(),
            lid.as_ptr(),
            lid.len(),
            slt.as_mut_ptr(),
            slt.len(),
            sst.as_mut_ptr(),
            sst.len(),
            et.as_mut_ptr(),
            et.len(),
            hk.as_mut_ptr(),
            hk.len(),
            cet.as_mut_ptr(),
            cet.len(),
        )
    };
    if evaluated != 0
        || et != expected_et
        || sst != expected_sst
        || slt != expected_slt
        || hk != expected_hk
        || cet != expected_cet
    {
        return Err(DaaError::InvalidTpmProof);
    }

    let level = config.security.bits();
    let profile = config.tpm_sha_profile.code();
    let proof_cap = unsafe { daa_tpm_sha_chen23_sign_proof_bytes(level, profile) };
    if proof_cap == 0 {
        return Err(DaaError::InvalidTpmProof);
    }
    let randomness = fresh_prover_randomness()?;
    let mut proof = vec![0u8; proof_cap];
    let mut proof_len = proof.len();
    let ret = unsafe {
        daa_tpm_sha_chen23_sign_prove(
            level,
            profile,
            sk.as_ptr(),
            sk.len(),
            sid.as_ptr(),
            sid.len(),
            gid.as_ptr(),
            gid.len(),
            lid.as_ptr(),
            lid.len(),
            expected_slt.as_ptr(),
            expected_slt.len(),
            expected_hk.as_ptr(),
            expected_hk.len(),
            expected_cet.as_ptr(),
            expected_cet.len(),
            sid.as_ptr(),
            sid.len(),
            randomness.as_ptr(),
            randomness.len(),
            proof.as_mut_ptr(),
            &mut proof_len,
        )
    };
    if ret != 0 || proof_len > proof.len() {
        return Err(DaaError::InvalidTpmProof);
    }
    proof.truncate(proof_len);
    Ok(ProofArtifact {
        kind: "pi_tpm".to_string(),
        backend: format!(
            "voleith-{}{}-cdenw23-5sha2",
            sha2_name(config.security),
            config.tpm_sha_profile.name()
        ),
        statement_hash: sha2_hash(
            SecurityLevel::L128,
            &[sid, gid, lid, expected_slt, expected_hk, expected_cet],
        ),
        proof_bytes: proof,
        seal_bytes: None,
    })
}

/// Verifies the public CDENW'23--Ours-5F statement, including the shared cet.
#[allow(clippy::too_many_arguments)]
fn verify_tpm_sha_chen23_real(
    config: &ProtocolConfig,
    proof: &ProofArtifact,
    lid: &[u8],
    gid: &[u8],
    slt: &[u8],
    hk: &[u8],
    cet: &[u8],
    sid: &[u8],
) -> bool {
    unsafe {
        daa_tpm_sha_chen23_sign_verify(
            config.security.bits(),
            config.tpm_sha_profile.code(),
            sid.as_ptr(),
            sid.len(),
            gid.as_ptr(),
            gid.len(),
            lid.as_ptr(),
            lid.len(),
            slt.as_ptr(),
            slt.len(),
            hk.as_ptr(),
            hk.len(),
            cet.as_ptr(),
            cet.len(),
            sid.as_ptr(),
            sid.len(),
            proof.proof_bytes.as_ptr(),
            proof.proof_bytes.len(),
        ) == 0
    }
}

/// Produces the real FAEST single-AES join proof.
fn prove_join_aes_real(
    config: &ProtocolConfig,
    sk: &[u8],
    gid: &[u8],
    et: &[u8],
    msg: &[u8],
) -> DaaResult<ProofArtifact> {
    let spec = config.param_spec()?;
    let mut proof = vec![0u8; unsafe { daa_join_sig_bytes(spec.lambda, spec.fast as i32) }];
    let mut proof_len = proof.len();
    let ret = unsafe {
        daa_join_prove(
            spec.lambda,
            spec.fast as i32,
            sk.as_ptr(),
            gid.as_ptr(),
            et.as_ptr(),
            msg.as_ptr(),
            msg.len(),
            proof.as_mut_ptr(),
            &mut proof_len,
        )
    };
    if ret != 0 {
        return Err(DaaError::InvalidJoinProof);
    }
    proof.truncate(proof_len);
    Ok(ProofArtifact {
        kind: "pi_join".to_string(),
        backend: format!("faest-{}-single-aes", spec.faest_suffix()),
        statement_hash: hash_many(32, &[gid, et, msg]),
        proof_bytes: proof,
        seal_bytes: None,
    })
}

/// Verifies the real FAEST single-AES join proof.
fn verify_join_aes_real(
    config: &ProtocolConfig,
    proof: &ProofArtifact,
    gid: &[u8],
    et: &[u8],
    msg: &[u8],
) -> bool {
    let Ok(spec) = config.param_spec() else {
        return false;
    };
    unsafe {
        daa_join_verify(
            spec.lambda,
            spec.fast as i32,
            gid.as_ptr(),
            et.as_ptr(),
            msg.as_ptr(),
            msg.len(),
            proof.proof_bytes.as_ptr(),
            proof.proof_bytes.len(),
        ) == 0
    }
}

/// Produces the real FAEST TPM signing proof.
fn prove_tpm_aes_real(
    config: &ProtocolConfig,
    lid: &[u8],
    gid: &[u8],
    sk: &[u8],
    s: &[u8],
    msg_prime: &[u8],
    expected_et: &[u8],
    expected_slt: &[u8],
    expected_hk: &[u8],
) -> DaaResult<ProofArtifact> {
    let spec = config.param_spec()?;
    let token_len = config.security.token_bytes();
    let mut et = vec![0u8; token_len];
    let mut slt = vec![0u8; token_len];
    let mut hk = vec![0u8; token_len];
    let mut proof = vec![0u8; unsafe { daa_tpm_sig_bytes(spec.lambda, spec.fast as i32) }];
    let mut proof_len = proof.len();
    let ret = unsafe {
        daa_tpm_prove(
            spec.lambda,
            spec.fast as i32,
            lid.as_ptr(),
            gid.as_ptr(),
            sk.as_ptr(),
            s.as_ptr(),
            msg_prime.as_ptr(),
            msg_prime.len(),
            et.as_mut_ptr(),
            slt.as_mut_ptr(),
            hk.as_mut_ptr(),
            proof.as_mut_ptr(),
            &mut proof_len,
        )
    };
    if ret != 0 || et != expected_et || slt != expected_slt || hk != expected_hk {
        return Err(DaaError::InvalidTpmProof);
    }
    proof.truncate(proof_len);
    Ok(ProofArtifact {
        kind: "pi_tpm".to_string(),
        backend: format!("faest-{}-3aes", spec.faest_suffix()),
        statement_hash: hash_many(32, &[lid, gid, expected_slt, expected_hk, msg_prime]),
        proof_bytes: proof,
        seal_bytes: None,
    })
}

/// Verifies the real FAEST TPM signing proof.
fn verify_tpm_aes_real(
    config: &ProtocolConfig,
    proof: &ProofArtifact,
    lid: &[u8],
    gid: &[u8],
    slt: &[u8],
    hk: &[u8],
    msg_prime: &[u8],
) -> bool {
    let Ok(spec) = config.param_spec() else {
        return false;
    };
    unsafe {
        daa_tpm_verify(
            spec.lambda,
            spec.fast as i32,
            lid.as_ptr(),
            gid.as_ptr(),
            slt.as_ptr(),
            hk.as_ptr(),
            msg_prime.as_ptr(),
            msg_prime.len(),
            proof.proof_bytes.as_ptr(),
            proof.proof_bytes.len(),
        ) == 0
    }
}

/// Runs the RISC0 SHA-256-backend host prover.
fn prove_host_risc0_128s(
    config: &ProtocolConfig,
    issuer_pk: &[u8],
    credential_sig: &[u8],
    hk: &[u8],
    cet: &[u8],
    hook_secret: &[u8],
    et: &[u8],
    issuer_nonce: &[u8],
) -> DaaResult<HostProofResult> {
    let input = HostProofInput {
        issuer_pk,
        credential_sig,
        hk,
        cet,
        hook_secret,
        et,
        issuer_nonce,
    };
    run_host_proof_command(config, "prove-protocol", &input, None)
}

/// Runs the RISC0 SHA-256-backend host verifier.
fn verify_host_risc0_128s(
    config: &ProtocolConfig,
    proof: &ProofArtifact,
    issuer_pk: &[u8],
    hk: &[u8],
    cet: &[u8],
) -> DaaResult<HostVerifyResult> {
    let input = HostProofInput {
        issuer_pk,
        credential_sig: &[],
        hk,
        cet,
        hook_secret: &[],
        et: &[],
        issuer_nonce: &[],
    };
    let out = run_host_proof_command(config, "verify-protocol", &input, Some(&proof.proof_bytes))?;
    Ok(HostVerifyResult {
        accepted: out.accepted,
        verifier_millis: out.verifier_millis,
    })
}

struct HostProofInput<'a> {
    issuer_pk: &'a [u8],
    credential_sig: &'a [u8],
    hk: &'a [u8],
    cet: &'a [u8],
    hook_secret: &'a [u8],
    et: &'a [u8],
    issuer_nonce: &'a [u8],
}

#[derive(Debug, Clone)]
struct HostProofResult {
    proof_bytes: Bytes,
    seal_bytes: Option<usize>,
    accepted: bool,
    prover_millis: u128,
    verifier_millis: u128,
}

#[derive(Debug, Clone)]
struct HostVerifyResult {
    accepted: bool,
    verifier_millis: u128,
}

#[derive(Debug, Clone)]
struct IssuerSignResult {
    signature: Bytes,
    sign_millis: u128,
}

/// Native certificate material exported by the credential implementation.
#[derive(Debug, Clone)]
struct IssuerAnchorNative {
    certificate: Bytes,
    witness: Bytes,
    public_a: Bytes,
    public_b: Bytes,
    anchor_value: Bytes,
    generation: Duration,
    certificate_verify: Duration,
}

/// Combined external issuer key-generation and anchor-construction result.
#[derive(Debug, Clone)]
struct IssuerSetupAnchorExternal {
    pk: Bytes,
    sk: Bytes,
    keygen: Duration,
    anchor: IssuerAnchorNative,
}

/// Maps the selected credential scheme to the stable issuer-anchor ABI tag.
fn issuer_anchor_kind(config: &ProtocolConfig) -> u32 {
    match config.credential_scheme {
        CredentialScheme::SphincsPlus => 1,
        CredentialScheme::FSphincsPlus => 2,
    }
}

/// Domain-separates and binds pi_I to one issuer key and public certificate.
fn issuer_anchor_context(config: &ProtocolConfig, pk: &[u8], certificate: &[u8]) -> Bytes {
    let mut hash = Sha256::new();
    hash.update(b"DAA-ISSUER-ANCHOR-PI-v1");
    hash.update([issuer_anchor_kind(config) as u8]);
    hash.update(config.security.bits().to_be_bytes());
    hash.update(config.sphincs_params.as_bytes());
    hash.update((pk.len() as u64).to_be_bytes());
    hash.update(pk);
    hash.update((certificate.len() as u64).to_be_bytes());
    hash.update(certificate);
    hash.finalize().to_vec()
}

/// Generates the real VOLEith pi_I for the native dual-anchor statement.
fn prove_issuer_anchor_real(
    config: &ProtocolConfig,
    native: &IssuerAnchorNative,
    context: &[u8],
) -> DaaResult<ProofArtifact> {
    let level = config.security.bits();
    let profile = config.tpm_sha_profile.code();
    let kind = issuer_anchor_kind(config);
    let proof_capacity = unsafe { daa_issuer_anchor_proof_bytes(level, profile, kind) };
    if proof_capacity == 0 {
        return Err(DaaError::InvalidIssuerAnchor);
    }
    let mut proof = vec![0u8; proof_capacity];
    let mut proof_len = proof.len();
    let mut rng = DeterministicRng::new(
        config.deterministic_seed ^ stable_u64(&native.certificate) ^ 0x5049_5f49,
    );
    let randomness = rng.bytes(32);
    let ret = unsafe {
        daa_issuer_anchor_prove(
            level,
            profile,
            kind,
            native.witness.as_ptr(),
            native.witness.len(),
            native.public_a.as_ptr(),
            native.public_a.len(),
            native.public_b.as_ptr(),
            native.public_b.len(),
            native.anchor_value.as_ptr(),
            native.anchor_value.len(),
            context.as_ptr(),
            context.len(),
            randomness.as_ptr(),
            randomness.len(),
            proof.as_mut_ptr(),
            &mut proof_len,
        )
    };
    if ret != 0 {
        return Err(DaaError::InvalidIssuerAnchor);
    }
    proof.truncate(proof_len);
    Ok(ProofArtifact {
        kind: "pi_i".to_string(),
        backend: format!(
            "voleith-sha256-issuer-anchor-{}-{}{}",
            config.credential_scheme.name(),
            config.security.bits(),
            config.tpm_sha_profile.name(),
        ),
        statement_hash: hash_many(
            32,
            &[
                &native.public_a,
                &native.public_b,
                &native.anchor_value,
                context,
            ],
        ),
        proof_bytes: proof,
        seal_bytes: None,
    })
}

/// Verifies pi_I and its Rust-side statement binding.
fn verify_issuer_anchor_real(
    config: &ProtocolConfig,
    native: &IssuerAnchorNative,
    context: &[u8],
    proof: &ProofArtifact,
) -> bool {
    let expected_statement = hash_many(
        32,
        &[
            &native.public_a,
            &native.public_b,
            &native.anchor_value,
            context,
        ],
    );
    proof.statement_hash == expected_statement
        && unsafe {
            daa_issuer_anchor_verify(
                config.security.bits(),
                config.tpm_sha_profile.code(),
                issuer_anchor_kind(config),
                native.public_a.as_ptr(),
                native.public_a.len(),
                native.public_b.as_ptr(),
                native.public_b.len(),
                native.anchor_value.as_ptr(),
                native.anchor_value.len(),
                context.as_ptr(),
                context.len(),
                proof.proof_bytes.as_ptr(),
                proof.proof_bytes.len(),
            ) == 0
        }
}

/// Runs native issuer key generation and deterministic anchor construction.
fn issuer_setup_anchor_external(config: &ProtocolConfig) -> DaaResult<IssuerSetupAnchorExternal> {
    let stamp = HOST_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let output_path = std::env::temp_dir().join(format!("sedaa-issuer-setup-anchor-{stamp}.out"));
    let mut cmd = host_cargo_command(config)?;
    cmd.arg("issuer-setup-anchor").arg(&output_path);
    let output = cmd.output().map_err(|_| DaaError::ExternalHostProof)?;
    if !output.status.success() {
        eprintln!(
            "external issuer setup anchor failed:\n{}",
            command_text(&output)
        );
        let _ = std::fs::remove_file(&output_path);
        return Err(DaaError::ExternalHostProof);
    }
    let parts =
        read_length_prefixed_parts(&output_path).map_err(|_| DaaError::ExternalHostProof)?;
    let _ = std::fs::remove_file(&output_path);
    if parts.len() != 7 {
        return Err(DaaError::ExternalHostProof);
    }
    let text = command_text(&output);
    Ok(IssuerSetupAnchorExternal {
        pk: parts[0].clone(),
        sk: parts[1].clone(),
        keygen: Duration::from_micros(parse_metric_u128(&text, "keygen_us").unwrap_or(0) as u64),
        anchor: IssuerAnchorNative {
            certificate: parts[2].clone(),
            witness: parts[3].clone(),
            public_a: parts[4].clone(),
            public_b: parts[5].clone(),
            anchor_value: parts[6].clone(),
            generation: Duration::from_micros(
                parse_metric_u128(&text, "anchor_generation_us").unwrap_or(0) as u64,
            ),
            certificate_verify: Duration::from_micros(
                parse_metric_u128(&text, "certificate_verify_us").unwrap_or(0) as u64,
            ),
        },
    })
}

/// Runs SPHINCS+ issuer credential signing in the parameterized host fork.
fn issuer_sign_external(
    config: &ProtocolConfig,
    sk: &[u8],
    msg: &[u8],
) -> DaaResult<IssuerSignResult> {
    let stamp = HOST_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir();
    let input_path = dir.join(format!("sedaa-issuer-sign-{stamp}.in"));
    let output_path = dir.join(format!("sedaa-issuer-sign-{stamp}.out"));
    write_length_prefixed_parts(&input_path, &[sk, msg])
        .map_err(|_| DaaError::ExternalHostProof)?;
    let mut cmd = host_cargo_command(config)?;
    cmd.arg("issuer-sign").arg(&input_path).arg(&output_path);
    let output = cmd.output().map_err(|_| DaaError::ExternalHostProof)?;
    let _ = std::fs::remove_file(&input_path);
    if !output.status.success() {
        let _ = std::fs::remove_file(&output_path);
        return Err(DaaError::ExternalHostProof);
    }
    let parts =
        read_length_prefixed_parts(&output_path).map_err(|_| DaaError::ExternalHostProof)?;
    let _ = std::fs::remove_file(&output_path);
    if parts.len() != 1 {
        return Err(DaaError::ExternalHostProof);
    }
    let text = command_text(&output);
    Ok(IssuerSignResult {
        signature: parts[0].clone(),
        sign_millis: parse_metric_u128(&text, "sign_ms").unwrap_or(0),
    })
}

/// Launches the external RISC0 host proof binary with benchmark-compatible settings.
fn run_host_proof_command(
    config: &ProtocolConfig,
    mode: &str,
    input: &HostProofInput<'_>,
    receipt: Option<&[u8]>,
) -> DaaResult<HostProofResult> {
    let stamp = HOST_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir();
    let input_path = dir.join(format!("sedaa-host-proof-{stamp}.bin"));
    let receipt_path = dir.join(format!("sedaa-host-proof-{stamp}.receipt"));
    write_host_input(config, &input_path, input).map_err(|_| DaaError::ExternalHostProof)?;
    if let Some(bytes) = receipt {
        std::fs::write(&receipt_path, bytes).map_err(|_| DaaError::ExternalHostProof)?;
    }

    let mut cmd = host_cargo_command(config)?;
    cmd.arg(mode).arg(&input_path).arg(&receipt_path);
    let output = cmd.output().map_err(|_| DaaError::ExternalHostProof)?;
    let _ = std::fs::remove_file(&input_path);
    if !output.status.success() {
        eprintln!("external host proof failed:\n{}", command_text(&output));
        let _ = std::fs::remove_file(&receipt_path);
        return Err(DaaError::ExternalHostProof);
    }
    let text = command_text(&output);
    let metrics = parse_host_metrics(&text);
    if mode == "prove-protocol" {
        let proof = std::fs::read(&receipt_path).map_err(|_| DaaError::ExternalHostProof)?;
        let _ = std::fs::remove_file(&receipt_path);
        Ok(HostProofResult {
            proof_bytes: proof,
            seal_bytes: metrics.seal_bytes,
            accepted: metrics.accepted,
            prover_millis: metrics.prover_millis,
            verifier_millis: metrics.verifier_millis,
        })
    } else {
        let _ = std::fs::remove_file(&receipt_path);
        Ok(HostProofResult {
            proof_bytes: Vec::new(),
            seal_bytes: None,
            accepted: metrics.accepted,
            prover_millis: metrics.prover_millis,
            verifier_millis: metrics.verifier_millis,
        })
    }
}

/// Builds the external host-fork cargo command with shared cache settings.
fn host_cargo_command(config: &ProtocolConfig) -> DaaResult<Command> {
    let manifest = daa_full_root().join("host_proof/host/Cargo.toml");
    let mut cmd = Command::new("cargo");
    cmd.arg("run")
        .arg("--quiet")
        .arg("--manifest-path")
        .arg(manifest)
        .arg("--release")
        .arg("--features")
        .arg("cuda")
        .arg("--bin")
        .arg("daa_sha256_backend_host")
        .arg("--")
        .env("RISC0_PROVER", "local")
        .env("SPHINCS_PARAMS", config.param_spec()?.sphincs_env)
        .env("SPHINCS_THASH", "simple")
        .env(
            "SPHINCS_OPT_LEVEL",
            std::env::var("SPHINCS_OPT_LEVEL").unwrap_or_else(|_| "2".to_string()),
        )
        .env("DAA_DETERMINISTIC", "1")
        .env("DAA_TPM_BACKEND", config.tpm_backend.name())
        .env("DAA_TPM_SHA_SCHEME", config.tpm_sha_scheme.name())
        .env("DAA_CREDENTIAL_SCHEME", config.credential_scheme.name())
        .env("FSPHINCS_SECURITY", config.security.bits().to_string())
        .env(
            "FSPHINCS_K",
            match config.security {
                SecurityLevel::L128 => "22",
                SecurityLevel::L192 => "33",
                SecurityLevel::L256 => "43",
            },
        )
        .env("RISC0_BACKEND_HASH", &config.backend_hash);
    if let Some(segment_limit_po2) = config.risc0_segment_limit_po2 {
        cmd.env("RISC0_SEGMENT_LIMIT_PO2", segment_limit_po2.to_string());
    }
    if std::env::var_os("CARGO_TARGET_DIR").is_none() {
        let target_dir = std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|home| home.join(".cache/sedaa-risc0-shared-target"))
            .unwrap_or_else(|| std::env::temp_dir().join("sedaa-risc0-shared-target"));
        cmd.env("CARGO_TARGET_DIR", target_dir);
    }
    Ok(cmd)
}

/// Combines stdout and stderr from an external command.
fn command_text(output: &std::process::Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[derive(Debug, Clone, Copy)]
struct HostMetrics {
    accepted: bool,
    prover_millis: u128,
    verifier_millis: u128,
    seal_bytes: Option<usize>,
}

/// Parses key-value metrics emitted by the RISC0 host proof runner.
fn parse_host_metrics(output: &str) -> HostMetrics {
    HostMetrics {
        accepted: parse_metric_bool(output, "accepted").unwrap_or_else(|| output.contains("ok")),
        prover_millis: parse_metric_u128(output, "prover_ms").unwrap_or(0),
        verifier_millis: parse_metric_u128(output, "verifier_ms").unwrap_or(0),
        seal_bytes: parse_metric_u128(output, "seal_bytes").and_then(|v| v.try_into().ok()),
    }
}

/// Parses an unsigned integer metric from external runner output.
fn parse_metric_u128(output: &str, key: &str) -> Option<u128> {
    parse_metric_value(output, key).and_then(|value| value.parse().ok())
}

/// Parses a boolean metric from external runner output.
fn parse_metric_bool(output: &str, key: &str) -> Option<bool> {
    parse_metric_value(output, key).and_then(|value| match value {
        "1" | "true" | "ok" => Some(true),
        "0" | "false" => Some(false),
        _ => None,
    })
}

/// Parses a raw key-value metric from external runner output.
fn parse_metric_value<'a>(output: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key}=");
    output
        .lines()
        .find_map(|line| line.trim().strip_prefix(&prefix).map(str::trim))
}

/// Writes a length-prefixed binary input file for the RISC0 host runner.
fn write_host_input(
    config: &ProtocolConfig,
    path: &PathBuf,
    input: &HostProofInput<'_>,
) -> std::io::Result<()> {
    if config.tpm_sha_scheme == TpmShaScheme::Cdenw23Ours5F {
        write_length_prefixed_parts(
            path,
            &[
                input.issuer_pk,
                input.credential_sig,
                input.hk,
                input.cet,
                input.hook_secret,
                input.et,
                input.issuer_nonce,
            ],
        )
    } else {
        write_length_prefixed_parts(
            path,
            &[
                input.issuer_pk,
                input.credential_sig,
                input.hk,
                input.hook_secret,
                input.et,
                input.issuer_nonce,
            ],
        )
    }
}

/// Writes a length-prefixed sequence of byte strings.
fn write_length_prefixed_parts(path: &PathBuf, parts: &[&[u8]]) -> std::io::Result<()> {
    let mut file = std::fs::File::create(path)?;
    for part in parts {
        file.write_all(&(part.len() as u64).to_le_bytes())?;
        file.write_all(part)?;
    }
    Ok(())
}

/// Reads a length-prefixed sequence of byte strings.
fn read_length_prefixed_parts(path: &PathBuf) -> std::io::Result<Vec<Bytes>> {
    let bytes = std::fs::read(path)?;
    let mut pos = 0usize;
    let mut parts = Vec::new();
    while pos < bytes.len() {
        if pos + 8 > bytes.len() {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        let mut len_bytes = [0u8; 8];
        len_bytes.copy_from_slice(&bytes[pos..pos + 8]);
        pos += 8;
        let len = u64::from_le_bytes(len_bytes) as usize;
        if pos + len > bytes.len() {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        parts.push(bytes[pos..pos + len].to_vec());
        pos += len;
    }
    Ok(parts)
}

/// Returns the standalone DAA_FULL project root.
fn daa_full_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("daa_core path")
        .to_path_buf()
}

static HOST_TMP_COUNTER: AtomicU64 = AtomicU64::new(1);

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct DaaTpmShaStats {
    private_input_bits: usize,
    public_input_bits: usize,
    output_bits: usize,
    and_gates: usize,
    xor_gates: usize,
    total_nodes: usize,
    proof_bytes: usize,
}

/// Provides deterministic randombytes for linked C code in local benchmarks.
#[no_mangle]
pub unsafe extern "C" fn randombytes(out: *mut u8, outlen: usize) {
    static SEED: AtomicU64 = AtomicU64::new(0x5eed_daa5_2026_0705);
    let mut rng = DeterministicRng::new(SEED.fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed));
    let slice = std::slice::from_raw_parts_mut(out, outlen);
    for byte in slice {
        *byte = rng.next_u8();
    }
}

extern "C" {
    fn daa_aes_owf(lambda: u32, key: *const u8, input: *const u8, output: *mut u8);
    fn daa_aes_hook(lambda: u32, key: *const u8, input: *const u8, output: *mut u8);
    fn daa_join_sig_bytes(lambda: u32, fast: i32) -> usize;
    fn daa_tpm_sig_bytes(lambda: u32, fast: i32) -> usize;
    fn daa_join_prove(
        lambda: u32,
        fast: i32,
        sk_u: *const u8,
        gid: *const u8,
        et: *const u8,
        msg: *const u8,
        msg_len: usize,
        sig: *mut u8,
        sig_len: *mut usize,
    ) -> i32;
    fn daa_join_verify(
        lambda: u32,
        fast: i32,
        gid: *const u8,
        et: *const u8,
        msg: *const u8,
        msg_len: usize,
        sig: *const u8,
        sig_len: usize,
    ) -> i32;
    fn daa_tpm_prove(
        lambda: u32,
        fast: i32,
        lid: *const u8,
        gid: *const u8,
        sk_u: *const u8,
        s: *const u8,
        msg: *const u8,
        msg_len: usize,
        et_out: *mut u8,
        slt_out: *mut u8,
        hk_out: *mut u8,
        sig: *mut u8,
        sig_len: *mut usize,
    ) -> i32;
    fn daa_tpm_verify(
        lambda: u32,
        fast: i32,
        lid: *const u8,
        gid: *const u8,
        slt: *const u8,
        hk: *const u8,
        msg: *const u8,
        msg_len: usize,
        sig: *const u8,
        sig_len: usize,
    ) -> i32;
    fn daa_tpm_sha_prepare(level: u32, profile: u32) -> i32;
    fn daa_tpm_sha_join_stats(level: u32, profile: u32, stats: *mut DaaTpmShaStats) -> i32;
    fn daa_tpm_sha_sign_stats(level: u32, profile: u32, stats: *mut DaaTpmShaStats) -> i32;
    fn daa_tpm_sha_join_proof_bytes(level: u32, profile: u32) -> usize;
    fn daa_tpm_sha_sign_proof_bytes(level: u32, profile: u32) -> usize;
    fn daa_tpm_sha_join_prove(
        level: u32,
        profile: u32,
        sk: *const u8,
        sk_len: usize,
        gid: *const u8,
        gid_len: usize,
        et: *const u8,
        et_len: usize,
        context: *const u8,
        context_len: usize,
        randomness: *const u8,
        randomness_len: usize,
        proof_out: *mut u8,
        proof_len: *mut usize,
    ) -> i32;
    fn daa_tpm_sha_join_verify(
        level: u32,
        profile: u32,
        gid: *const u8,
        gid_len: usize,
        et: *const u8,
        et_len: usize,
        context: *const u8,
        context_len: usize,
        proof: *const u8,
        proof_len: usize,
    ) -> i32;
    fn daa_tpm_sha_sign_prove(
        level: u32,
        profile: u32,
        sk: *const u8,
        sk_len: usize,
        s: *const u8,
        s_len: usize,
        lid: *const u8,
        lid_len: usize,
        gid: *const u8,
        gid_len: usize,
        slt: *const u8,
        slt_len: usize,
        hk: *const u8,
        hk_len: usize,
        context: *const u8,
        context_len: usize,
        randomness: *const u8,
        randomness_len: usize,
        proof_out: *mut u8,
        proof_len: *mut usize,
    ) -> i32;
    fn daa_tpm_sha_sign_verify(
        level: u32,
        profile: u32,
        lid: *const u8,
        lid_len: usize,
        gid: *const u8,
        gid_len: usize,
        slt: *const u8,
        slt_len: usize,
        hk: *const u8,
        hk_len: usize,
        context: *const u8,
        context_len: usize,
        proof: *const u8,
        proof_len: usize,
    ) -> i32;
    fn daa_issuer_anchor_prepare(level: u32, profile: u32, kind: u32) -> i32;
    fn daa_issuer_anchor_stats(
        level: u32,
        profile: u32,
        kind: u32,
        stats: *mut DaaTpmShaStats,
    ) -> i32;
    fn daa_issuer_anchor_proof_bytes(level: u32, profile: u32, kind: u32) -> usize;
    fn daa_issuer_anchor_prove(
        level: u32,
        profile: u32,
        kind: u32,
        seed: *const u8,
        seed_len: usize,
        public_a: *const u8,
        public_a_len: usize,
        public_b: *const u8,
        public_b_len: usize,
        anchor_value: *const u8,
        anchor_value_len: usize,
        context: *const u8,
        context_len: usize,
        randomness: *const u8,
        randomness_len: usize,
        proof_out: *mut u8,
        proof_len: *mut usize,
    ) -> i32;
    fn daa_issuer_anchor_verify(
        level: u32,
        profile: u32,
        kind: u32,
        public_a: *const u8,
        public_a_len: usize,
        public_b: *const u8,
        public_b_len: usize,
        anchor_value: *const u8,
        anchor_value_len: usize,
        context: *const u8,
        context_len: usize,
        proof: *const u8,
        proof_len: usize,
    ) -> i32;
    fn daa_tpm_sha_chen23_prepare(level: u32, profile: u32) -> i32;
    fn daa_tpm_sha_chen23_sign_proof_bytes(level: u32, profile: u32) -> usize;
    fn daa_tpm_sha_chen23_evaluate_sign(
        level: u32,
        sk: *const u8,
        sk_len: usize,
        sid: *const u8,
        sid_len: usize,
        gid: *const u8,
        gid_len: usize,
        lid: *const u8,
        lid_len: usize,
        slt_out: *mut u8,
        slt_len: usize,
        sst_out: *mut u8,
        sst_len: usize,
        et_out: *mut u8,
        et_len: usize,
        hk_out: *mut u8,
        hk_len: usize,
        cet_out: *mut u8,
        cet_len: usize,
    ) -> i32;
    fn daa_tpm_sha_chen23_sign_prove(
        level: u32,
        profile: u32,
        sk: *const u8,
        sk_len: usize,
        sid: *const u8,
        sid_len: usize,
        gid: *const u8,
        gid_len: usize,
        lid: *const u8,
        lid_len: usize,
        slt: *const u8,
        slt_len: usize,
        hk: *const u8,
        hk_len: usize,
        cet: *const u8,
        cet_len: usize,
        context: *const u8,
        context_len: usize,
        randomness: *const u8,
        randomness_len: usize,
        proof_out: *mut u8,
        proof_len: *mut usize,
    ) -> i32;
    fn daa_tpm_sha_chen23_sign_verify(
        level: u32,
        profile: u32,
        sid: *const u8,
        sid_len: usize,
        gid: *const u8,
        gid_len: usize,
        lid: *const u8,
        lid_len: usize,
        slt: *const u8,
        slt_len: usize,
        hk: *const u8,
        hk_len: usize,
        cet: *const u8,
        cet_len: usize,
        context: *const u8,
        context_len: usize,
        proof: *const u8,
        proof_len: usize,
    ) -> i32;
}

/// Builds a deterministic simulated proof artifact for fast protocol tests.
fn simulated_proof(
    kind: &str,
    backend: &str,
    proof_len: usize,
    statement_parts: &[&[u8]],
    witness_parts: &[&[u8]],
) -> ProofArtifact {
    let statement_hash = hash_many(32, statement_parts);
    let witness_hash = hash_many(32, witness_parts);
    let proof_bytes = hash_many(
        proof_len.max(32),
        &[
            kind.as_bytes(),
            backend.as_bytes(),
            &statement_hash,
            &witness_hash,
        ],
    );
    ProofArtifact {
        kind: kind.to_string(),
        backend: backend.to_string(),
        statement_hash,
        proof_bytes,
        seal_bytes: None,
    }
}

/// Verifies a simulated proof when witnesses are still locally available.
fn verify_simulated_proof(
    proof: &ProofArtifact,
    statement_parts: &[&[u8]],
    witness_parts: &[&[u8]],
) -> bool {
    let expected = simulated_proof(
        &proof.kind,
        &proof.backend,
        proof.proof_bytes.len(),
        statement_parts,
        witness_parts,
    );
    proof.statement_hash == expected.statement_hash && proof.proof_bytes == expected.proof_bytes
}

/// Verifies only the public statement hash of a proof artifact.
fn verify_statement_only(proof: &ProofArtifact, statement_parts: &[&[u8]]) -> bool {
    proof.statement_hash == hash_many(32, statement_parts)
}

/// Expands a stable hash transcript to an arbitrary byte length.
fn hash_many(out_len: usize, parts: &[&[u8]]) -> Bytes {
    let mut out = Vec::with_capacity(out_len);
    let mut counter = 0u64;
    while out.len() < out_len {
        let mut hasher = DefaultHasher::new();
        counter.hash(&mut hasher);
        for part in parts {
            part.len().hash(&mut hasher);
            part.hash(&mut hasher);
        }
        out.extend_from_slice(&hasher.finish().to_le_bytes());
        counter += 1;
    }
    out.truncate(out_len);
    out
}

/// Hashes a byte slice into a stable u64 value.
fn stable_u64(bytes: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    bytes.hash(&mut hasher);
    hasher.finish()
}

/// Converts a boolean into a one-byte witness marker.
fn bool_byte(value: bool) -> [u8; 1] {
    [u8::from(value)]
}

/// Escapes a string for the small handwritten JSON output.
fn json_escape(input: &str) -> String {
    input.replace('\\', "\\\\").replace('"', "\\\"")
}

struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    /// Creates a deterministic xorshift RNG from a seed.
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Produces the next deterministic u64.
    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    /// Produces the next deterministic byte.
    fn next_u8(&mut self) -> u8 {
        self.next_u64() as u8
    }

    /// Produces a deterministic byte vector of the requested length.
    fn bytes(&mut self, len: usize) -> Bytes {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            out.extend_from_slice(&self.next_u64().to_le_bytes());
        }
        out.truncate(len);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_aes_lengths_and_identifiers_are_unchanged() {
        let config = ProtocolConfig::default().with_params("sha2-192s");
        assert_eq!(config.tpm_backend, TpmBackend::Aes);
        assert_eq!(config.tpm_token_bytes(), 32);
        assert_eq!(config.issuer_nonce_bytes(), 32);
        assert_eq!(
            group_id(&config, b"pk"),
            hash_many(16, &[b"gid", b"pk", b"sha2-192s"])
        );
        assert_eq!(
            link_id(&config, b"bsn"),
            hash_many(16, &[b"lid", b"bsn", b"sha2-192s"])
        );
    }

    #[test]
    fn sha_backend_uses_full_digest_lengths_and_domain_separation() {
        for (params, key_len, digest_len) in [
            ("sha2-128s", 16, 32),
            ("sha2-192s", 24, 48),
            ("sha2-256s", 32, 64),
        ] {
            let config = ProtocolConfig::default()
                .with_params(params)
                .with_tpm_backend(TpmBackend::Sha2);
            assert_eq!(config.security.key_bytes(), key_len);
            assert_eq!(config.tpm_token_bytes(), digest_len);
            assert_eq!(config.issuer_nonce_bytes(), key_len);

            let sk = vec![0x11; key_len];
            let s = vec![0x22; key_len];
            let gid = group_id(&config, b"pk");
            let lid = link_id(&config, b"basename");
            assert_eq!(gid.len(), digest_len);
            assert_eq!(lid.len(), digest_len);
            assert_ne!(gid, lid);

            let values = tpm_sign_values(&config, &sk, &s, b"sid", &lid, &gid);
            assert_eq!(values.et, sha2_hash(config.security, &[&[0x02], &sk, &gid]));
            assert_eq!(
                values.slt,
                sha2_hash(config.security, &[&[0x01], &sk, &lid])
            );
            assert_eq!(
                values.hk,
                sha2_hash(config.security, &[&[0x03], &s, &values.et])
            );
            assert!(values.cet.is_empty());
            assert_eq!(values.et.len(), digest_len);
            assert_eq!(values.slt.len(), digest_len);
            assert_eq!(values.hk.len(), digest_len);
        }
    }

    #[test]
    fn legacy_aes_real_proofs_still_round_trip() {
        let config = ProtocolConfig::default()
            .with_params("sha2-128s")
            .with_tpm_backend(TpmBackend::Aes)
            .with_proof_mode(ProofMode::RealTpm);
        let mut sk = vec![0x31; config.security.key_bytes()];
        let mut s = vec![0x72; config.security.key_bytes()];
        normalize_faest_key(&mut sk);
        normalize_faest_key(&mut s);
        let gid = vec![0x43; 16];
        let lid = vec![0x54; 16];
        let et = aes_prf(&config, &sk, &gid);
        let join_context = join_proof_message(&config, &gid, &et);
        let join = prove_join_aes_real(&config, &sk, &gid, &et, &join_context).unwrap();
        assert!(verify_join_aes_real(
            &config,
            &join,
            &gid,
            &et,
            &join_context
        ));

        let context = message_prime(&config, b"legacy AES KAT", b"fixed rho");
        let values = tpm_sign_values(&config, &sk, &s, &context, &lid, &gid);
        let proof = prove_tpm_aes_real(
            &config,
            &lid,
            &gid,
            &sk,
            &s,
            &context,
            &values.et,
            &values.slt,
            &values.hk,
        )
        .unwrap();
        assert!(verify_tpm_aes_real(
            &config,
            &proof,
            &lid,
            &gid,
            &values.slt,
            &values.hk,
            &context
        ));
    }

    #[test]
    fn cdenw23_values_bind_join_et_and_both_host_hooks() {
        let config = ProtocolConfig::default()
            .with_tpm_backend(TpmBackend::Sha2)
            .with_tpm_sha_scheme(TpmShaScheme::Cdenw23Ours5F)
            .with_credential_scheme(CredentialScheme::FSphincsPlus);
        let sk = vec![0x31; config.security.key_bytes()];
        let gid = group_id(&config, b"issuer-pk");
        let lid = link_id(&config, b"basename");
        let sid = message_prime(&config, b"message", b"rho");
        let values = tpm_sign_values(&config, &sk, b"unused", &sid, &lid, &gid);

        assert_eq!(values.et, tpm_et(&config, &sk, &gid));
        assert_eq!(
            values.hook_secret,
            sha2_hash(config.security, &[&[0x04], &sk, &sid])
        );
        assert_eq!(
            (values.hk.clone(), values.cet.clone()),
            host_hook_outputs(&config, &values.hook_secret, &values.et)
        );
        assert_eq!(values.cet.len(), config.tpm_token_bytes());
    }
}
