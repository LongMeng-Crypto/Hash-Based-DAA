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

use alloc::{collections::BTreeSet, string::String, vec::Vec};

use anyhow::Result;
use borsh::{BorshDeserialize, BorshSerialize};
use derive_more::Debug;
use risc0_binfmt::{tagged_iter, tagged_struct, Digestible, PovwNonce};
use risc0_zkp::{
    adapter::{CircuitInfo as _, ProtocolInfo, PROOF_SYSTEM_INFO},
    core::{digest::Digest, hash::sha::Sha256},
    verify::VerificationError,
};
use serde::{Deserialize, Serialize};

use super::VerifierContext;
use crate::{sha, ReceiptClaim};

#[derive(Clone, Debug, Deserialize, Serialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(test, derive(PartialEq))]
#[non_exhaustive]
pub struct SegmentReceipt {

    #[debug("{} bytes", self.get_seal_bytes().len())]
    pub seal: Vec<u32>,

    pub index: u32,

    pub hashfn: String,

    pub verifier_parameters: Digest,

    pub claim: ReceiptClaim,
}

impl SegmentReceipt {

    // Verifies integrity with context.
    pub fn verify_integrity_with_context(
        &self,
        ctx: &VerifierContext,
    ) -> Result<(), VerificationError> {
        let params = ctx
            .segment_verifier_parameters
            .as_ref()
            .ok_or(VerificationError::VerifierParametersMissing)?;

        if params.proof_system_info != PROOF_SYSTEM_INFO {
            return Err(VerificationError::ProofSystemInfoMismatch {
                expected: PROOF_SYSTEM_INFO,
                received: params.proof_system_info,
            });
        }

        let expected = risc0_circuit_rv32im::CircuitImpl::CIRCUIT_INFO;

        if params.circuit_info != expected {
            return Err(VerificationError::CircuitInfoMismatch {
                expected,
                received: params.circuit_info,
            });
        }

        let suite = ctx
            .suites
            .get(&self.hashfn)
            .ok_or(VerificationError::InvalidHashSuite)?;

        tracing::debug!("SegmentReceipt::verify_integrity_with_context");
        risc0_circuit_rv32im::verify_with_hash_suite(&self.seal, suite)?;
        let decoded_claim = ReceiptClaim::decode_from_seal_v2(&self.seal, None)
            .or(Err(VerificationError::ReceiptFormatError))?;

        if decoded_claim.digest::<sha::Impl>() != self.claim.digest::<sha::Impl>() {
            tracing::debug!(
                "decoded segment receipt claim does not match claim field:\ndecoded: {:#?},\nexpected: {:#?}",
                decoded_claim,
                self.claim,
            );
            return Err(VerificationError::ClaimDigestMismatch {
                expected: self.claim.digest::<sha::Impl>(),
                received: decoded_claim.digest::<sha::Impl>(),
            });
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

    // Implements povw nonce.
    pub fn povw_nonce(&self) -> anyhow::Result<PovwNonce> {
        risc0_circuit_rv32im::decode_povw_nonce(&self.seal)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SegmentReceiptVerifierParameters {

    pub control_ids: BTreeSet<Digest>,

    pub proof_system_info: ProtocolInfo,

    pub circuit_info: ProtocolInfo,
}

impl Digestible for SegmentReceiptVerifierParameters {

    // Implements digest.
    fn digest<S: Sha256>(&self) -> Digest {
        tagged_struct::<S>(
            "risc0.SegmentReceiptVerifierParameters",
            &[
                tagged_iter::<S>("risc0.ControlIdSet", self.control_ids.iter()),
                *S::hash_bytes(&self.proof_system_info.0),
                *S::hash_bytes(&self.circuit_info.0),
            ],
            &[],
        )
    }
}

impl Default for SegmentReceiptVerifierParameters {

    // Implements default.
    fn default() -> Self {
        Self {
            control_ids: BTreeSet::default(),
            proof_system_info: PROOF_SYSTEM_INFO,
            circuit_info: risc0_circuit_rv32im::CircuitImpl::CIRCUIT_INFO,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SegmentReceiptVerifierParameters;
    use crate::sha::Digestible;
    use risc0_zkp::core::digest::digest;

    #[test]

    // Implements segment receipt verifier parameters is stable.
    fn segment_receipt_verifier_parameters_is_stable() {
        assert_eq!(
            SegmentReceiptVerifierParameters::default().digest(),
            digest!("e7300130165ebe00f68f9301530de9d068d6f6c06f1c17817a5f7d64ce6c635d")
        );
    }
}
