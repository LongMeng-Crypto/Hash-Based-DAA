// Copyright 2025 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

pub mod zkr;

use std::{
    collections::{BTreeMap, VecDeque},
    fmt::Debug,
    sync::Mutex,
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use risc0_binfmt::read_sha_halfs;
use risc0_circuit_recursion::{
    control_id::BN254_IDENTITY_CONTROL_ID,
    prove::{DigestKind, RecursionReceipt},
    CircuitImpl,
};
use risc0_circuit_rv32im::RV32IM_SEAL_VERSION;
use risc0_zkp::{
    adapter::{CircuitInfo, PROOF_SYSTEM_INFO},
    core::{
        digest::{Digest, DIGEST_SHORTS},
        hash::hash_suite_from_name,
    },
    field::baby_bear::BabyBearElem,
    verify::ReadIOP,
};

use crate::{
    claim::{
        merge::Merge,
        receipt::{Assumption, UnionClaim},
        Unknown,
    },
    receipt::{
        merkle::{MerkleGroup, MerkleProof},
        SegmentReceipt, SuccinctReceipt, SuccinctReceiptVerifierParameters,
    },
    sha::Digestible,
    Assumptions, MaybePruned, Output, ProverOpts, ReceiptClaim, WorkClaim,
};

use risc0_circuit_recursion::prove::Program;

pub const RECURSION_PO2: usize = 18;

pub(crate) type ZkrRegistryEntry = Box<dyn Fn() -> Result<Program> + Send + 'static>;

pub(crate) type ZkrRegistry = BTreeMap<Digest, ZkrRegistryEntry>;

pub(crate) static ZKR_REGISTRY: Mutex<ZkrRegistry> = Mutex::new(BTreeMap::new());

// Implements lift.
pub fn lift(segment_receipt: &SegmentReceipt) -> Result<SuccinctReceipt<ReceiptClaim>> {
    tracing::debug!("Proving lift: claim = {:#?}", segment_receipt.claim);
    let mut prover = Prover::new_lift(
        segment_receipt,
        recursion_opts_for_hashfn(&segment_receipt.hashfn)?,
    )?;

    let receipt = prover.prover.run()?;
    let claim_decoded = ReceiptClaim::decode(&mut receipt.out_stream())?;
    tracing::debug!("Proving lift finished: decoded claim = {claim_decoded:#?}");

    let claim = claim_decoded.merge(&segment_receipt.claim)?;

    make_succinct_receipt(prover, receipt, claim)
}

// Implements lift povw.
pub fn lift_povw(
    segment_receipt: &SegmentReceipt,
) -> Result<SuccinctReceipt<WorkClaim<ReceiptClaim>>> {
    tracing::debug!("Proving lift_povw: claim = {:#?}", segment_receipt.claim);
    let mut prover = Prover::new_lift_povw(
        segment_receipt,
        recursion_opts_for_hashfn(&segment_receipt.hashfn)?,
    )?;

    let receipt = prover.prover.run()?;
    let mut out_stream = receipt.out_stream();
    tracing::debug!("Proving lift_povw finished: out = {out_stream:?}");
    let claim_decoded = WorkClaim::<ReceiptClaim>::decode_from_seal(&mut out_stream)?;
    tracing::debug!("Proving lift_povw finished: decoded claim = {claim_decoded:#?}");

    let mut claim = claim_decoded;
    claim
        .claim
        .merge_with(&segment_receipt.claim.clone().into())
        .context("failed to merge segment receipt claim into decode claim")?;

    make_succinct_receipt(prover, receipt, claim)
}

// Implements join.
pub fn join(
    a: &SuccinctReceipt<ReceiptClaim>,
    b: &SuccinctReceipt<ReceiptClaim>,
) -> Result<SuccinctReceipt<ReceiptClaim>> {
    tracing::debug!("Proving join: a.claim = {:#?}", a.claim);
    tracing::debug!("Proving join: b.claim = {:#?}", b.claim);

    let mut prover = Prover::new_join(a, b, recursion_opts_for_hashfn(&a.hashfn)?)?;
    let receipt = prover.prover.run()?;

    let claim_decoded = ReceiptClaim::decode(&mut receipt.out_stream())?;
    tracing::debug!("Proving join finished: decoded claim = {claim_decoded:#?}");

    let claim = claim_decoded.merge(&a.claim.join(&b.claim)?.value()?)?;

    make_succinct_receipt(prover, receipt, claim)
}

// Implements join povw.
pub fn join_povw(
    a: &SuccinctReceipt<WorkClaim<ReceiptClaim>>,
    b: &SuccinctReceipt<WorkClaim<ReceiptClaim>>,
) -> Result<SuccinctReceipt<WorkClaim<ReceiptClaim>>> {
    tracing::debug!("Proving join_povw: a.claim = {:#?}", a.claim);
    tracing::debug!("Proving join_povw: b.claim = {:#?}", b.claim);

    let mut prover = Prover::new_join_povw(a, b, false, recursion_opts_for_hashfn(&a.hashfn)?)?;
    let receipt = prover.prover.run()?;

    let claim_decoded = WorkClaim::<ReceiptClaim>::decode_from_seal(&mut receipt.out_stream())?;
    tracing::debug!("Proving join_povw finished: decoded claim = {claim_decoded:#?}");

    let claim = claim_decoded.merge(&a.claim.join(&b.claim)?.value()?)?;

    make_succinct_receipt(prover, receipt, claim)
}

// Implements join unwrap povw.
pub fn join_unwrap_povw(
    a: &SuccinctReceipt<WorkClaim<ReceiptClaim>>,
    b: &SuccinctReceipt<WorkClaim<ReceiptClaim>>,
) -> Result<SuccinctReceipt<ReceiptClaim>> {
    tracing::debug!("Proving join_unwrap_povw: a.claim = {:#?}", a.claim);
    tracing::debug!("Proving join_unwrap_povw: b.claim = {:#?}", b.claim);

    let mut prover = Prover::new_join_povw(a, b, true, recursion_opts_for_hashfn(&a.hashfn)?)?;
    let receipt = prover.prover.run()?;

    let claim_decoded = ReceiptClaim::decode(&mut receipt.out_stream())?;
    tracing::debug!("Proving join_unwrap_povw finished: decoded claim = {claim_decoded:#?}");

    let claim = claim_decoded.merge(&a.claim.join(&b.claim)?.value()?.claim.value()?)?;

    make_succinct_receipt(prover, receipt, claim)
}

// Implements union.
pub fn union(
    a: &SuccinctReceipt<Unknown>,
    b: &SuccinctReceipt<Unknown>,
) -> Result<SuccinctReceipt<UnionClaim>> {

    let a_assumption = a.to_assumption(false)?.digest();
    let b_assumption = b.to_assumption(false)?.digest();

    let ((left_assumption, left_receipt), (right_assumption, right_receipt)) =
        if a_assumption <= b_assumption {
            ((a_assumption, a), (b_assumption, b))
        } else {
            ((b_assumption, b), (a_assumption, a))
        };

    tracing::debug!("Proving union: left assumption = {:#?}", left_assumption);
    tracing::debug!("Proving union: right assumption = {:#?}", right_assumption);

    let mut prover = Prover::new_union(
        left_receipt,
        right_receipt,
        recursion_opts_for_hashfn(&left_receipt.hashfn)?,
    )?;
    let receipt = prover.prover.run()?;

    let claim = UnionClaim {
        left: left_assumption,
        right: right_assumption,
    };

    make_succinct_receipt(prover, receipt, claim)
}

// Implements resolve.
pub fn resolve<Claim>(
    conditional: &SuccinctReceipt<ReceiptClaim>,
    assumption: &SuccinctReceipt<Claim>,
) -> Result<SuccinctReceipt<ReceiptClaim>>
where
    Claim: risc0_binfmt::Digestible + Debug,
{
    tracing::debug!(
        "Proving resolve: conditional.claim = {:#?}",
        conditional.claim,
    );
    tracing::debug!(
        "Proving resolve: assumption.claim = {:#?}",
        assumption.claim,
    );

    let mut prover = Prover::new_resolve(
        conditional,
        assumption,
        recursion_opts_for_hashfn(&conditional.hashfn)?,
    )?;
    let receipt = prover.prover.run()?;
    let claim_decoded = ReceiptClaim::decode(&mut receipt.out_stream())?;
    tracing::debug!("Proving resolve finished: decoded claim = {claim_decoded:#?}");

    let claim = conditional
        .claim
        .as_value()
        .context("conditional receipt claim is pruned")?
        .resolve(&assumption.claim)
        .context("failed to compute resolved claim")?
        .merge(&claim_decoded)
        .context("failed to merge resolved and decoded claims")?;

    make_succinct_receipt(prover, receipt, claim)
}

// Implements resolve povw.
pub fn resolve_povw<Claim>(
    conditional: &SuccinctReceipt<WorkClaim<ReceiptClaim>>,
    assumption: &SuccinctReceipt<Claim>,
) -> Result<SuccinctReceipt<WorkClaim<ReceiptClaim>>>
where
    Claim: risc0_binfmt::Digestible + Debug,
{
    tracing::debug!(
        "Proving resolve_povw: conditional.claim = {:#?}",
        conditional.claim,
    );
    tracing::debug!(
        "Proving resolve_povw: assumption.claim = {:#?}",
        assumption.claim,
    );

    let mut prover = Prover::new_resolve_povw(
        conditional,
        assumption,
        false,
        recursion_opts_for_hashfn(&conditional.hashfn)?,
    )?;
    let receipt = prover.prover.run()?;
    let claim_decoded = WorkClaim::<ReceiptClaim>::decode_from_seal(&mut receipt.out_stream())?;
    tracing::debug!("Proving resolve_povw finished: decoded claim = {claim_decoded:#?}");

    let claim = conditional
        .claim
        .as_value()
        .context("conditional receipt povw claim is pruned")?
        .resolve(&assumption.claim)
        .context("failed to compute resolved claim")?
        .merge(&claim_decoded)
        .context("failed to merge resolved and decoded claims")?;

    make_succinct_receipt(prover, receipt, claim)
}

// Implements resolve unwrap povw.
pub fn resolve_unwrap_povw<Claim>(
    conditional: &SuccinctReceipt<WorkClaim<ReceiptClaim>>,
    assumption: &SuccinctReceipt<Claim>,
) -> Result<SuccinctReceipt<ReceiptClaim>>
where
    Claim: risc0_binfmt::Digestible + Debug,
{
    tracing::debug!(
        "Proving resolve_unwrap_povw: conditional.claim = {:#?}",
        conditional.claim,
    );
    tracing::debug!(
        "Proving resolve_unwrap_povw: assumption.claim = {:#?}",
        assumption.claim,
    );

    let mut prover = Prover::new_resolve_povw(
        conditional,
        assumption,
        true,
        recursion_opts_for_hashfn(&conditional.hashfn)?,
    )?;
    let receipt = prover.prover.run()?;
    let claim_decoded = ReceiptClaim::decode(&mut receipt.out_stream())?;
    tracing::debug!("Proving resolve_unwrap_povw finished: decoded claim = {claim_decoded:#?}");

    let claim = conditional
        .claim
        .as_value()
        .context("conditional receipt povw claim is pruned")?
        .claim
        .as_value()
        .context("conditional receipt claim is pruned")?
        .resolve(&assumption.claim)
        .context("failed to compute resolved claim")?
        .merge(&claim_decoded)
        .context("failed to merge resolved and decoded claims")?;

    make_succinct_receipt(prover, receipt, claim)
}

// Implements unwrap povw.
pub fn unwrap_povw(
    a: &SuccinctReceipt<WorkClaim<ReceiptClaim>>,
) -> Result<SuccinctReceipt<ReceiptClaim>> {
    tracing::debug!("Proving unwrap_povw: a.claim = {:#?}", a.claim);

    let mut prover = Prover::new_unwrap_povw(a, recursion_opts_for_hashfn(&a.hashfn)?)?;
    let receipt = prover.prover.run()?;

    let claim_decoded = ReceiptClaim::decode(&mut receipt.out_stream())?;
    tracing::debug!("Proving unwrap_povw finished: decoded claim = {claim_decoded:#?}");

    let claim = MaybePruned::Value(claim_decoded).merge(&a.claim.as_value()?.claim)?;

    make_succinct_receipt(prover, receipt, claim)
}

// Implements identity p254.
pub fn identity_p254(
    inner: &SuccinctReceipt<ReceiptClaim>,
) -> Result<SuccinctReceipt<ReceiptClaim>> {
    tracing::debug!("identity_p254");

    let opts = ProverOpts::succinct()
        .with_hashfn("poseidon_254".to_string())
        .with_control_ids(vec![BN254_IDENTITY_CONTROL_ID]);
    let mut prover = Prover::new_identity(inner, opts)?;
    let receipt = prover.prover.run()?;
    let claim =
        MaybePruned::Value(ReceiptClaim::decode(&mut receipt.out_stream())?).merge(&inner.claim)?;

    let hashfn = prover.opts.hash_suite()?.hashfn;
    let control_inclusion_proof = prover.control_inclusion_proof()?;
    let control_root = control_inclusion_proof.root(&prover.control_id, hashfn.as_ref());
    let params = SuccinctReceiptVerifierParameters {
        control_root,
        inner_control_root: Some(inner.control_root()?),
        proof_system_info: PROOF_SYSTEM_INFO,
        circuit_info: CircuitImpl::CIRCUIT_INFO,
    };

    Ok(SuccinctReceipt {
        seal: receipt.seal,
        hashfn: prover.opts.hashfn.clone(),
        control_id: prover.control_id,
        control_inclusion_proof,
        claim,
        verifier_parameters: params.digest(),
    })
}

// Implements identity.
pub fn identity(inner: &SuccinctReceipt<ReceiptClaim>) -> Result<SuccinctReceipt<ReceiptClaim>> {
    tracing::debug!("identity");

    let opts = recursion_opts_for_hashfn(&inner.hashfn)?;
    let mut prover = Prover::new_identity(inner, opts)?;
    let receipt = prover.prover.run()?;
    let claim =
        MaybePruned::Value(ReceiptClaim::decode(&mut receipt.out_stream())?).merge(&inner.claim)?;

    make_succinct_receipt(prover, receipt, claim)
}

// Proves zkr.
pub fn prove_zkr(
    program: Program,
    control_id: &Digest,
    allowed_control_ids: Vec<Digest>,
    input: &[u8],
) -> Result<SuccinctReceipt<Unknown>> {
    let opts = ProverOpts::succinct().with_control_ids(allowed_control_ids);
    let mut prover = Prover::new(program, *control_id, opts.clone());
    prover.add_input(bytemuck::cast_slice(input));

    tracing::debug!("Running prover");
    let receipt = prover.run()?;

    tracing::trace!("zkr receipt: {receipt:?}");

    let claim_digest: Digest = read_sha_halfs(&mut VecDeque::from_iter(
        bytemuck::checked::cast_slice::<_, BabyBearElem>(
            &receipt.seal[DIGEST_SHORTS..2 * DIGEST_SHORTS],
        )
        .iter()
        .copied()
        .map(u32::from),
    ))?;

    let hashfn = opts.hash_suite()?.hashfn;
    let control_group = MerkleGroup::new(opts.control_ids.clone())?;
    let control_root = control_group.calc_root(hashfn.as_ref());
    let control_inclusion_proof = control_group.get_proof(control_id, hashfn.as_ref())?;

    let verifier_parameters = SuccinctReceiptVerifierParameters {
        control_root,
        inner_control_root: None,
        proof_system_info: PROOF_SYSTEM_INFO,
        circuit_info: CircuitImpl::CIRCUIT_INFO,
    }
    .digest();

    Ok(SuccinctReceipt {
        seal: receipt.seal,
        hashfn: opts.hashfn,
        control_id: *control_id,
        control_inclusion_proof,
        claim: MaybePruned::<Unknown>::Pruned(claim_digest),
        verifier_parameters,
    })
}

// Proves registered zkr.
pub fn prove_registered_zkr(
    control_id: &Digest,
    allowed_control_ids: Vec<Digest>,
    input: &[u8],
) -> Result<SuccinctReceipt<Unknown>> {
    let zkr = get_registered_zkr(control_id)?;
    prove_zkr(zkr, control_id, allowed_control_ids, input)
}

// Implements register zkr.
pub fn register_zkr(
    control_id: &Digest,
    get_program_fn: impl Fn() -> Result<Program> + Send + 'static,
) -> Option<ZkrRegistryEntry> {
    let mut registry = ZKR_REGISTRY.lock().unwrap();
    registry.insert(*control_id, Box::new(get_program_fn))
}

// Returns registered zkr.
pub fn get_registered_zkr(control_id: &Digest) -> Result<Program> {
    let registry = ZKR_REGISTRY.lock().unwrap();
    registry
        .get(control_id)
        .map(|f| f())
        .unwrap_or_else(|| bail!("Control id {control_id} unregistered"))
}

// Creates succinct receipt.
fn make_succinct_receipt<Claim>(
    prover: Prover,
    receipt: RecursionReceipt,
    claim: impl Into<MaybePruned<Claim>>,
) -> Result<SuccinctReceipt<Claim>> {
    let hashfn = prover.opts.hash_suite()?.hashfn;
    let control_inclusion_proof = prover.control_inclusion_proof()?;
    let control_root = control_inclusion_proof.root(&prover.control_id, hashfn.as_ref());
    let params = SuccinctReceiptVerifierParameters {
        control_root,
        inner_control_root: None,
        proof_system_info: PROOF_SYSTEM_INFO,
        circuit_info: CircuitImpl::CIRCUIT_INFO,
    };

    Ok(SuccinctReceipt {
        seal: receipt.seal,
        hashfn: prover.opts.hashfn.clone(),
        control_id: prover.control_id,
        control_inclusion_proof,
        claim: claim.into(),
        verifier_parameters: params.digest(),
    })
}

#[cfg(test)]

// Tests zkr.
pub fn test_zkr(
    digest1: &Digest,
    digest2: &Digest,
    po2: usize,
) -> Result<SuccinctReceipt<crate::claim::Unknown>> {
    use risc0_circuit_recursion::prove::zkr::get_zkr;
    use risc0_zkp::core::hash::poseidon2::Poseidon2HashSuite;

    let program = get_zkr("test_recursion_circuit.zkr", po2)?;
    let suite = Poseidon2HashSuite::new_suite();
    let control_id = program.compute_control_id(suite.clone()).unwrap();
    let opts = ProverOpts::succinct().with_control_ids(vec![control_id]);

    let mut prover = Prover::new(program, control_id, opts.clone());
    prover.add_input_digest(digest1, DigestKind::Poseidon2);
    prover.add_input_digest(digest2, DigestKind::Poseidon2);

    let receipt = prover.run()?;

    let claim_digest = read_sha_halfs(&mut VecDeque::from_iter(
        bytemuck::checked::cast_slice::<_, BabyBearElem>(
            &receipt.seal[DIGEST_SHORTS..2 * DIGEST_SHORTS],
        )
        .iter()
        .copied()
        .map(u32::from),
    ))?;

    let hashfn = opts.hash_suite()?.hashfn;
    let control_inclusion_proof = MerkleGroup::new(opts.control_ids.clone())?
        .get_proof(&prover.control_id, hashfn.as_ref())?;
    let control_root = control_inclusion_proof.root(&prover.control_id, hashfn.as_ref());
    let params = SuccinctReceiptVerifierParameters {
        control_root,
        inner_control_root: Some(digest1.to_owned()),
        proof_system_info: PROOF_SYSTEM_INFO,
        circuit_info: CircuitImpl::CIRCUIT_INFO,
    };
    Ok(SuccinctReceipt {
        seal: receipt.seal,
        hashfn: suite.name,
        control_id: prover.control_id,
        control_inclusion_proof,
        claim: MaybePruned::Pruned(claim_digest),
        verifier_parameters: params.digest(),
    })
}

pub struct Prover {
    prover: risc0_circuit_recursion::prove::Prover,
    control_id: Digest,
    opts: ProverOpts,
}

// Implements digest kind for hashfn.
fn digest_kind_for_hashfn(hashfn: &str) -> Result<DigestKind> {
    match hashfn {
        "poseidon2" => Ok(DigestKind::Poseidon2),
        "sha-256" => Ok(DigestKind::Sha256),
        _ => bail!("recursion programs do not support hashfn {hashfn}"),
    }
}

// Implements ensure recursion hashfn.
fn ensure_recursion_hashfn(hashfn: &str) -> Result<()> {
    digest_kind_for_hashfn(hashfn).map(|_| ())
}

// Implements recursion opts for hashfn.
fn recursion_opts_for_hashfn(hashfn: &str) -> Result<ProverOpts> {
    let opts = ProverOpts::succinct().with_hashfn(hashfn.to_string());
    let control_ids =
        crate::receipt::succinct::allowed_control_ids(hashfn.to_string(), opts.max_segment_po2)?
            .collect();
    Ok(opts.with_control_ids(control_ids))
}

impl Prover {

    // Creates the operation result.
    pub(crate) fn new(program: Program, control_id: Digest, opts: ProverOpts) -> Self {
        Self {
            prover: risc0_circuit_recursion::prove::Prover::new(program, &opts.hashfn),
            control_id,
            opts,
        }
    }

    // Implements control id.
    pub fn control_id(&self) -> &Digest {
        &self.control_id
    }

    // Implements control inclusion proof.
    pub fn control_inclusion_proof(&self) -> Result<MerkleProof> {
        let hashfn = self
            .opts
            .hash_suite()
            .context("ProverOpts contains invalid hashfn")?
            .hashfn;
        MerkleGroup::new(self.opts.control_ids.clone())?
            .get_proof(&self.control_id, hashfn.as_ref())
    }

    // Creates test recursion circuit.
    pub fn new_test_recursion_circuit(digests: [&Digest; 2], opts: ProverOpts) -> Result<Self> {
        let (program, control_id) = zkr::test_recursion_circuit(&opts.hashfn)?;
        let mut prover = Prover::new(program, control_id, opts);

        for digest in digests {
            prover.add_input_digest(digest, DigestKind::Poseidon2);
        }

        Ok(prover)
    }

    // Creates lift.
    pub fn new_lift(segment: &SegmentReceipt, opts: ProverOpts) -> Result<Self> {
        Self::new_lift_inner(segment, opts, false)
    }

    // Creates lift povw.
    pub fn new_lift_povw(segment: &SegmentReceipt, opts: ProverOpts) -> Result<Self> {
        Self::new_lift_inner(segment, opts, true)
    }

    // Creates lift inner.
    fn new_lift_inner(segment: &SegmentReceipt, opts: ProverOpts, povw: bool) -> Result<Self> {
        ensure_recursion_hashfn(&segment.hashfn)?;

        let inner_hash_suite = hash_suite_from_name(&segment.hashfn)
            .ok_or_else(|| anyhow!("unsupported hash function: {}", segment.hashfn))?;
        let allowed_ids = MerkleGroup::new(opts.control_ids.clone())?;
        let merkle_root = allowed_ids.calc_root(inner_hash_suite.hashfn.as_ref());

        let out_size = risc0_circuit_rv32im::CircuitImpl::OUTPUT_SIZE;

        ensure!(
            segment.seal[0] == RV32IM_SEAL_VERSION,
            "seal version mismatch"
        );

        let seal = &segment.seal[1..];

        let mut iop = ReadIOP::new(seal, inner_hash_suite.rng.as_ref());
        iop.read_field_elem_slice::<BabyBearElem>(out_size)?;
        let po2 = *iop.read_u32s(1)?.first().unwrap() as usize;

        let (program, control_id) = match povw {
            false => zkr::lift(po2, &opts.hashfn)?,
            true => zkr::lift_povw(po2, &opts.hashfn)?,
        };
        let mut prover = Prover::new(program, control_id, opts);

        prover.add_input_digest(&merkle_root, DigestKind::Poseidon2);
        prover.add_input(seal);

        Ok(prover)
    }

    // Creates union.
    pub fn new_union(
        a: &SuccinctReceipt<Unknown>,
        b: &SuccinctReceipt<Unknown>,
        opts: ProverOpts,
    ) -> Result<Self> {
        ensure_recursion_hashfn(&a.hashfn)?;
        ensure_recursion_hashfn(&b.hashfn)?;

        ensure!(
            a.hashfn == b.hashfn,
            "receipt hash functions differ: {} != {}",
            a.hashfn,
            b.hashfn
        );

        let hash_suite = hash_suite_from_name(&a.hashfn)
            .ok_or_else(|| anyhow!("unsupported hash function: {}", a.hashfn))?;
        let allowed_ids = MerkleGroup::new(opts.control_ids.clone())?;
        let merkle_root = allowed_ids.calc_root(hash_suite.hashfn.as_ref());

        let (program, control_id) = zkr::union(&opts.hashfn)?;
        let mut prover = Prover::new(program, control_id, opts);

        prover.add_iop_digest(&merkle_root, digest_kind_for_hashfn(&a.hashfn)?)?;
        prover.add_succinct_generic_receipt(a)?;
        prover.add_succinct_generic_receipt(b)?;
        Ok(prover)
    }

    // Creates join.
    pub fn new_join(
        a: &SuccinctReceipt<ReceiptClaim>,
        b: &SuccinctReceipt<ReceiptClaim>,
        opts: ProverOpts,
    ) -> Result<Self> {
        ensure_recursion_hashfn(&a.hashfn)?;
        ensure_recursion_hashfn(&b.hashfn)?;

        ensure!(
            a.hashfn == b.hashfn,
            "receipt hash functions differ: {} != {}",
            a.hashfn,
            b.hashfn
        );

        let (program, control_id) = zkr::join(&opts.hashfn)?;
        let mut prover = Prover::new(program, control_id, opts);

        let merkle_root = a.control_root()?;
        ensure!(
            merkle_root == b.control_root()?,
            "merkle roots for a and b do not match: {} != {}",
            merkle_root,
            b.control_root()?
        );

        prover.add_iop_digest(&merkle_root, digest_kind_for_hashfn(&a.hashfn)?)?;
        prover.add_succinct_rv32im_receipt(a)?;
        prover.add_succinct_rv32im_receipt(b)?;
        Ok(prover)
    }

    // Creates join povw.
    pub fn new_join_povw(
        a: &SuccinctReceipt<WorkClaim<ReceiptClaim>>,
        b: &SuccinctReceipt<WorkClaim<ReceiptClaim>>,
        unwrap: bool,
        opts: ProverOpts,
    ) -> Result<Self> {
        ensure_recursion_hashfn(&a.hashfn)?;
        ensure_recursion_hashfn(&b.hashfn)?;

        ensure!(
            a.hashfn == b.hashfn,
            "receipt hash functions differ: {} != {}",
            a.hashfn,
            b.hashfn
        );

        let (program, control_id) = match unwrap {
            false => zkr::join_povw(&opts.hashfn)?,
            true => zkr::join_unwrap_povw(&opts.hashfn)?,
        };
        let mut prover = Prover::new(program, control_id, opts);

        let merkle_root = a.control_root()?;
        ensure!(
            merkle_root == b.control_root()?,
            "merkle roots for a and b do not match: {} != {}",
            merkle_root,
            b.control_root()?
        );

        prover.add_input_digest(&merkle_root, digest_kind_for_hashfn(&a.hashfn)?);
        prover.add_succinct_work_claim_rv32im_receipt(a)?;
        prover.add_succinct_work_claim_rv32im_receipt(b)?;
        Ok(prover)
    }

    // Creates resolve.
    pub fn new_resolve<Claim>(
        cond: &SuccinctReceipt<ReceiptClaim>,
        assum: &SuccinctReceipt<Claim>,
        opts: ProverOpts,
    ) -> Result<Self>
    where
        Claim: risc0_binfmt::Digestible + Debug,
    {
        ensure_recursion_hashfn(&cond.hashfn)?;
        ensure_recursion_hashfn(&assum.hashfn)?;

        let (program, control_id) = zkr::resolve(&opts.hashfn)?;
        let mut prover = Prover::new(program, control_id, opts);

        prover.add_input_digest(&cond.control_root()?, digest_kind_for_hashfn(&cond.hashfn)?);
        prover.add_succinct_rv32im_receipt(cond)?;

        let (head, tail, output) = check_resolve_assumption(&cond.claim, &assum.claim)?;

        let expected_root = match head.control_root == Digest::ZERO {
            true => cond.control_root()?,
            false => head.control_root,
        };
        ensure!(
            expected_root == assum.control_root()?,
            "assumption receipt control root does not match head of assumptions list"
        );

        prover.add_assumption_receipt(head, assum)?;
        prover.add_input_digest(&tail.digest(), DigestKind::Sha256);
        prover.add_input_digest(&output.journal.digest(), DigestKind::Sha256);
        Ok(prover)
    }

    // Creates resolve povw.
    pub fn new_resolve_povw<Claim>(
        cond: &SuccinctReceipt<WorkClaim<ReceiptClaim>>,
        assum: &SuccinctReceipt<Claim>,
        unwrap: bool,
        opts: ProverOpts,
    ) -> Result<Self>
    where
        Claim: risc0_binfmt::Digestible + Debug,
    {
        ensure_recursion_hashfn(&cond.hashfn)?;
        ensure_recursion_hashfn(&assum.hashfn)?;

        let (program, control_id) = match unwrap {
            false => zkr::resolve_povw(&opts.hashfn)?,
            true => zkr::resolve_unwrap_povw(&opts.hashfn)?,
        };
        let mut prover = Prover::new(program, control_id, opts);

        prover.add_input_digest(&cond.control_root()?, digest_kind_for_hashfn(&cond.hashfn)?);
        prover.add_succinct_work_claim_rv32im_receipt(cond)?;

        let cond_claim = &cond
            .claim
            .as_value()
            .context("cannot resolve assumption receipt with pruned work claim")?
            .claim;
        let (head, tail, output) = check_resolve_assumption(cond_claim, &assum.claim)?;

        let expected_root = match head.control_root == Digest::ZERO {
            true => cond.control_root()?,
            false => head.control_root,
        };
        ensure!(
            expected_root == assum.control_root()?,
            "assumption receipt control root does not match head of assumptions list"
        );

        prover.add_assumption_receipt(head, assum)?;
        prover.add_input_digest(&tail.digest(), DigestKind::Sha256);
        prover.add_input_digest(&output.journal.digest(), DigestKind::Sha256);
        Ok(prover)
    }

    // Creates identity.
    pub fn new_identity(a: &SuccinctReceipt<ReceiptClaim>, opts: ProverOpts) -> Result<Self> {
        ensure_recursion_hashfn(&a.hashfn)?;

        let (program, control_id) = zkr::identity(&opts.hashfn)?;
        let mut prover = Prover::new(program, control_id, opts);

        prover.add_iop_digest(&a.control_root()?, digest_kind_for_hashfn(&a.hashfn)?)?;
        prover.add_succinct_rv32im_receipt(a)?;
        Ok(prover)
    }

    // Creates unwrap povw.
    pub fn new_unwrap_povw(
        a: &SuccinctReceipt<WorkClaim<ReceiptClaim>>,
        opts: ProverOpts,
    ) -> Result<Self> {
        ensure_recursion_hashfn(&a.hashfn)?;

        let (program, control_id) = zkr::unwrap_povw(&opts.hashfn)?;
        let mut prover = Prover::new(program, control_id, opts);

        prover.add_input_digest(&a.control_root()?, digest_kind_for_hashfn(&a.hashfn)?);
        prover.add_succinct_work_claim_rv32im_receipt(a)?;
        Ok(prover)
    }

    // Adds input.
    pub(crate) fn add_input(&mut self, input: &[u32]) {
        self.prover.add_input(input)
    }

    // Adds input digest.
    fn add_input_digest(&mut self, digest: &Digest, kind: DigestKind) {
        self.prover.add_input_digest(digest, kind)
    }

    // Adds iop digest.
    fn add_iop_digest(&mut self, digest: &Digest, kind: DigestKind) -> Result<()> {
        match kind {
            DigestKind::Sha256 => self.add_input(digest.as_words()),
            DigestKind::Poseidon2 => self.add_input_digest(digest, DigestKind::Poseidon2),
            _ => bail!("unsupported recursion IOP digest kind"),
        }
        Ok(())
    }

    // Adds seal.
    pub fn add_seal(
        &mut self,
        seal: &[u32],
        control_id: &Digest,
        control_inclusion_proof: &MerkleProof,
        hashfn: &str,
    ) -> Result<()> {
        tracing::debug!("Control ID = {:?}", control_id);
        self.add_input(seal);
        tracing::debug!("index = {:?}", control_inclusion_proof.index);
        self.add_input(bytemuck::cast_slice(&[BabyBearElem::new(
            control_inclusion_proof.index,
        )]));
        for digest in &control_inclusion_proof.digests {
            tracing::debug!("path = {:?}", digest);
            self.add_iop_digest(digest, digest_kind_for_hashfn(hashfn)?)?;
        }
        Ok(())
    }

    // Adds assumption receipt.
    fn add_assumption_receipt<Claim>(
        &mut self,
        assumption: Assumption,
        receipt: &SuccinctReceipt<Claim>,
    ) -> Result<()> {
        self.add_seal(
            &receipt.seal,
            &receipt.control_id,
            &receipt.control_inclusion_proof,
            &receipt.hashfn,
        )?;

        let zero_root = BabyBearElem::new((assumption.control_root == Digest::ZERO) as u32);
        self.add_input(bytemuck::cast_slice(&[zero_root]));
        Ok(())
    }

    // Adds succinct work claim rv32im receipt.
    fn add_succinct_work_claim_rv32im_receipt(
        &mut self,
        a: &SuccinctReceipt<WorkClaim<ReceiptClaim>>,
    ) -> Result<()> {
        self.add_seal(
            &a.seal,
            &a.control_id,
            &a.control_inclusion_proof,
            &a.hashfn,
        )?;
        let mut data = Vec::<u32>::new();
        a.claim.as_value()?.encode_to_seal(&mut data)?;
        let data_fp: Vec<BabyBearElem> = data.iter().map(|x| BabyBearElem::new(*x)).collect();
        self.add_input(bytemuck::cast_slice(&data_fp));
        Ok(())
    }

    // Adds succinct rv32im receipt.
    fn add_succinct_rv32im_receipt(&mut self, a: &SuccinctReceipt<ReceiptClaim>) -> Result<()> {
        self.add_seal(
            &a.seal,
            &a.control_id,
            &a.control_inclusion_proof,
            &a.hashfn,
        )?;
        let mut data = Vec::<u32>::new();
        a.claim.as_value()?.encode(&mut data)?;
        let data_fp: Vec<BabyBearElem> = data.iter().map(|x| BabyBearElem::new(*x)).collect();
        self.add_input(bytemuck::cast_slice(&data_fp));
        Ok(())
    }

    // Adds succinct generic receipt.
    fn add_succinct_generic_receipt<Claim>(&mut self, a: &SuccinctReceipt<Claim>) -> Result<()> {
        self.add_seal(
            &a.seal,
            &a.control_id,
            &a.control_inclusion_proof,
            &a.hashfn,
        )?;

        let zero_root = BabyBearElem::new((a.control_root()? == Digest::ZERO) as u32);
        self.add_input(bytemuck::cast_slice(&[zero_root]));
        Ok(())
    }

    // Runs the operation result.
    pub fn run(&mut self) -> Result<RecursionReceipt> {
        self.prover.run()
    }
}

// Checks resolve assumption.
fn check_resolve_assumption<Claim>(
    cond: &MaybePruned<ReceiptClaim>,
    assum: &MaybePruned<Claim>,
) -> Result<(Assumption, Assumptions, Output)>
where
    Claim: risc0_binfmt::Digestible + Debug,
{
    let output = cond
        .as_value()
        .context("cannot resolve conditional receipt with pruned claim")?
        .output
        .as_value()
        .context("cannot resolve conditional receipt with pruned output")?
        .as_ref()
        .ok_or_else(|| anyhow!("cannot resolve conditional receipt with no output"))?
        .clone();

    let assumptions = output
        .assumptions
        .clone()
        .value()
        .context("cannot resolve conditional receipt with pruned assumptions")?;
    let head: Assumption = assumptions
        .0
        .first()
        .ok_or_else(|| anyhow!("cannot resolve conditional receipt with no assumptions"))?
        .as_value()
        .context("cannot resolve conditional receipt with pruned head assumption")?
        .clone();

    ensure!(
        head.claim == assum.digest(),
        "assumption receipt claim does not match head of assumptions list"
    );

    let mut assumptions_tail = assumptions;
    assumptions_tail.resolve(&head.digest())?;

    Ok((head, assumptions_tail, output))
}
