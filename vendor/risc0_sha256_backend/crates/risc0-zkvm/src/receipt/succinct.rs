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

use alloc::{
    collections::{BTreeSet, VecDeque},
    format,
    string::{String, ToString},
    vec::Vec,
};

use anyhow::bail;
use borsh::{BorshDeserialize, BorshSerialize};
use derive_more::Debug;
use risc0_binfmt::{read_sha_halfs, tagged_struct, Digestible};
use risc0_circuit_recursion::{
    control_id::{ALLOWED_CONTROL_ROOT, MIN_LIFT_PO2, POSEIDON2_CONTROL_IDS, SHA256_CONTROL_IDS},
    CircuitImpl, CIRCUIT,
};
use risc0_core::field::baby_bear::BabyBearElem;
use risc0_zkp::{
    adapter::{CircuitInfo, ProtocolInfo, PROOF_SYSTEM_INFO},
    core::{
        digest::Digest,
        hash::{hash_suite_from_name, sha::Sha256},
    },
    verify::VerificationError,
};
use serde::{Deserialize, Serialize};

use crate::{
    claim::Unknown,
    receipt::{
        merkle::{MerkleGroup, MerkleProof},
        VerifierContext,
    },
    sha, MaybePruned,
};

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(test, derive(PartialEq))]
#[non_exhaustive]
pub struct SuccinctReceipt<Claim> {

    #[debug("{} bytes", self.get_seal_bytes().len())]
    pub seal: Vec<u32>,

    pub control_id: Digest,

    pub claim: MaybePruned<Claim>,

    pub hashfn: String,

    pub verifier_parameters: Digest,

    pub control_inclusion_proof: MerkleProof,
}

impl<Claim> SuccinctReceipt<Claim> {

    // Verifies integrity.
    pub fn verify_integrity(&self) -> Result<(), VerificationError>
    where
        Claim: risc0_binfmt::Digestible + core::fmt::Debug,
    {
        self.verify_integrity_with_context(&VerifierContext::default())
    }

    // Verifies integrity with context.
    pub fn verify_integrity_with_context(
        &self,
        ctx: &VerifierContext,
    ) -> Result<(), VerificationError>
    where
        Claim: risc0_binfmt::Digestible + core::fmt::Debug,
    {
        let params = ctx
            .succinct_verifier_parameters
            .as_ref()
            .ok_or(VerificationError::VerifierParametersMissing)?;

        if params.digest::<sha::Impl>() != self.verifier_parameters {
            return Err(VerificationError::VerifierParametersMismatch {
                expected: params.digest::<sha::Impl>(),
                received: self.verifier_parameters,
            });
        }

        if params.proof_system_info != PROOF_SYSTEM_INFO {
            return Err(VerificationError::ProofSystemInfoMismatch {
                expected: PROOF_SYSTEM_INFO,
                received: params.proof_system_info,
            });
        }
        if params.circuit_info != CircuitImpl::CIRCUIT_INFO {
            return Err(VerificationError::CircuitInfoMismatch {
                expected: CircuitImpl::CIRCUIT_INFO,
                received: params.circuit_info,
            });
        }

        let suite = ctx
            .suites
            .get(&self.hashfn)
            .ok_or(VerificationError::InvalidHashSuite)?;

        let check_code = |_, control_id: &Digest| -> Result<(), VerificationError> {
            self.control_inclusion_proof
                .verify(control_id, &params.control_root, suite.hashfn.as_ref())
                .map_err(|_| {
                    tracing::debug!(
                        "failed to verify control inclusion proof for {control_id} against root {} with {}",
                        params.control_root,
                        suite.name,
                    );
                    VerificationError::ControlVerificationError {
                        control_id: *control_id,
                    }
                })
        };

        risc0_zkp::verify::verify(&CIRCUIT, suite, &self.seal, check_code)?;

        let output_elems: &[BabyBearElem] =
            bytemuck::checked::cast_slice(&self.seal[..CircuitImpl::OUTPUT_SIZE]);
        let mut seal_claim = VecDeque::new();
        for elem in output_elems {
            seal_claim.push_back(elem.as_u32())
        }

        let control_root = match self.hashfn.as_str() {
            "sha-256" => read_sha_halfs(&mut seal_claim)
                .map_err(|_| VerificationError::ReceiptFormatError)?,
            "poseidon2" => seal_claim
                .drain(0..16)
                .enumerate()
                .filter_map(|(i, word)| (i & 1 == 0).then_some(word))
                .collect::<Vec<_>>()
                .try_into()
                .map_err(|_| VerificationError::ReceiptFormatError)?,
            _ => return Err(VerificationError::InvalidHashSuite),
        };

        if control_root != params.inner_control_root.unwrap_or(params.control_root) {
            tracing::debug!(
                "succinct receipt does not match the expected control root: decoded: {:#?}, expected: {:?}",
                control_root,
                params.inner_control_root.unwrap_or(params.control_root),
            );
            return Err(VerificationError::ControlVerificationError {
                control_id: control_root,
            });
        }

        let output_hash =
            read_sha_halfs(&mut seal_claim).map_err(|_| VerificationError::ReceiptFormatError)?;
        if output_hash != self.claim.digest::<sha::Impl>() {
            tracing::debug!(
                "succinct receipt claim does not match the output digest: claim: {:#?}, digest expected: {output_hash:?}",
                self.claim,
            );
            return Err(VerificationError::JournalDigestMismatch);
        }

        Ok(())
    }

    // Returns seal bytes.
    pub fn get_seal_bytes(&self) -> Vec<u8> {
        self.seal.iter().flat_map(|x| x.to_le_bytes()).collect()
    }

    // Implements seal size.
    pub fn seal_size(&self) -> usize {
        core::mem::size_of_val(self.seal.as_slice())
    }

    #[cfg(feature = "prove")]

    // Implements control root.
    pub(crate) fn control_root(&self) -> anyhow::Result<Digest> {
        let hash_suite = hash_suite_from_name(&self.hashfn)
            .ok_or_else(|| anyhow::anyhow!("unsupported hash function: {}", self.hashfn))?;
        Ok(self
            .control_inclusion_proof
            .root(&self.control_id, hash_suite.hashfn.as_ref()))
    }

    #[cfg(feature = "prove")]

    // Implements to assumption.
    pub(crate) fn to_assumption(
        &self,
        erase_control_root: bool,
    ) -> anyhow::Result<crate::Assumption>
    where
        Claim: risc0_binfmt::Digestible,
    {
        Ok(crate::Assumption {
            claim: self.claim.digest::<sha::Impl>(),
            control_root: match erase_control_root {
                false => self.control_root()?,
                true => Digest::ZERO,
            },
        })
    }

    // Implements into unknown.
    pub fn into_unknown(self) -> SuccinctReceipt<Unknown>
    where
        Claim: risc0_binfmt::Digestible,
    {
        SuccinctReceipt {
            claim: MaybePruned::Pruned(self.claim.digest::<sha::Impl>()),
            seal: self.seal,
            control_id: self.control_id,
            hashfn: self.hashfn,
            verifier_parameters: self.verifier_parameters,
            control_inclusion_proof: self.control_inclusion_proof,
        }
    }
}

// Implements allowed control ids.
pub(crate) fn allowed_control_ids(
    hash_name: impl AsRef<str> + 'static,
    po2_max: usize,
) -> anyhow::Result<impl Iterator<Item = Digest>> {

    let po2_range = MIN_LIFT_PO2..=usize::min(po2_max, risc0_zkp::MAX_CYCLES_PO2);
    let allowed_zkr_names: BTreeSet<String> = [
        "join.zkr",
        "join_povw.zkr",
        "join_unwrap_povw.zkr",
        "resolve.zkr",
        "resolve_povw.zkr",
        "resolve_unwrap_povw.zkr",
        "identity.zkr",
        "unwrap_povw.zkr",
        "union.zkr",
    ]
    .map(str::to_string)
    .into_iter()
    .chain(po2_range.clone().map(|i| format!("lift_rv32im_v2_{i}.zkr")))
    .chain(po2_range.map(|i| format!("lift_rv32im_v2_povw_{i}.zkr")))
    .collect();

    let zkr_control_ids = match hash_name.as_ref() {
        "sha-256" => SHA256_CONTROL_IDS,
        "poseidon2" => POSEIDON2_CONTROL_IDS,
        _ => bail!(
            "unrecognized hash name for zkr control ids: {}",
            hash_name.as_ref()
        ),
    };

    Ok(allowed_zkr_names.into_iter().map(move |name| {
        *zkr_control_ids
            .iter()
            .find_map(|(zkr_name, digest)| (zkr_name == &name).then_some(digest))
            .expect("zkr name in allowed_zkr_names not found in zkr_control_ids")
    }))
}

// Implements allowed control root.
pub(crate) fn allowed_control_root(
    hash_name: impl AsRef<str> + 'static,
    po2_max: usize,
) -> anyhow::Result<Digest> {
    Ok(
        MerkleGroup::new(allowed_control_ids(hash_name.as_ref().to_string(), po2_max)?.collect())?
            .calc_root(
                hash_suite_from_name(hash_name.as_ref())
                    .unwrap()
                    .hashfn
                    .as_ref(),
            ),
    )
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SuccinctReceiptVerifierParameters {

    pub control_root: Digest,

    pub inner_control_root: Option<Digest>,

    pub proof_system_info: ProtocolInfo,

    pub circuit_info: ProtocolInfo,
}

impl SuccinctReceiptVerifierParameters {

    #[stability::unstable]

    // Implements from max po2.
    pub fn from_max_po2(po2_max: usize) -> Self {
        Self::from_max_po2_with_hashfn("poseidon2", po2_max).unwrap()
    }

    #[stability::unstable]

    // Implements from max po2 with hashfn.
    pub fn from_max_po2_with_hashfn(hashfn: &str, po2_max: usize) -> anyhow::Result<Self> {
        Ok(Self {
            control_root: allowed_control_root(hashfn.to_string(), po2_max)?,
            inner_control_root: None,
            proof_system_info: PROOF_SYSTEM_INFO,
            circuit_info: CircuitImpl::CIRCUIT_INFO,
        })
    }

    #[stability::unstable]

    // Implements all po2s.
    pub fn all_po2s() -> Self {
        Self::from_max_po2(risc0_zkp::MAX_CYCLES_PO2)
    }
}

impl Digestible for SuccinctReceiptVerifierParameters {

    // Implements digest.
    fn digest<S: Sha256>(&self) -> Digest {
        tagged_struct::<S>(
            "risc0.SuccinctReceiptVerifierParameters",
            &[
                self.control_root,
                self.inner_control_root.unwrap_or(self.control_root),
                *S::hash_bytes(&self.proof_system_info.0),
                *S::hash_bytes(&self.circuit_info.0),
            ],
            &[],
        )
    }
}

impl Default for SuccinctReceiptVerifierParameters {

    // Implements default.
    fn default() -> Self {
        Self {

            control_root: ALLOWED_CONTROL_ROOT,
            inner_control_root: None,
            proof_system_info: PROOF_SYSTEM_INFO,
            circuit_info: CircuitImpl::CIRCUIT_INFO,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{allowed_control_root, SuccinctReceiptVerifierParameters, ALLOWED_CONTROL_ROOT};
    use crate::{receipt::DEFAULT_MAX_PO2, sha::Digestible};
    use risc0_zkp::core::digest::digest;

    #[test]

    // Implements succinct receipt verifier parameters is stable.
    fn succinct_receipt_verifier_parameters_is_stable() {
        assert_eq!(
            SuccinctReceiptVerifierParameters::default().digest(),
            digest!("ece5e9b8ae2cd6ea6b1827b464ff0348f9a7f4decd269c0087fdfd75098da013")
        );
    }

    #[test]

    // Implements allowed control root fn matches bootstrap.
    fn allowed_control_root_fn_matches_bootstrap() {
        assert_eq!(
            allowed_control_root("poseidon2", DEFAULT_MAX_PO2).unwrap(),
            ALLOWED_CONTROL_ROOT
        )
    }

    #[test]

    // Implements allowed control root fn doesnt panic.
    fn allowed_control_root_fn_doesnt_panic() {
        for i in 0..=24 {
            allowed_control_root("poseidon2", i)
                .unwrap_or_else(|_| panic!("allowed_control_root panicked with i = {i}"));
        }

        assert_eq!(
            allowed_control_root("poseidon2", 24).unwrap(),
            allowed_control_root("poseidon2", 25).unwrap(),
        );
    }
}
