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

use alloc::{vec, vec::Vec};

use anyhow::Result;
use borsh::{BorshDeserialize, BorshSerialize};
use derive_more::Debug;
use risc0_binfmt::{tagged_struct, Digestible, ExitCode};
use risc0_circuit_recursion::CircuitImpl;
use risc0_zkp::{
    adapter::{CircuitInfo, PROOF_SYSTEM_INFO},
    core::{digest::Digest, hash::sha::Sha256},
    verify::VerificationError,
};
use serde::{Deserialize, Serialize};

use super::{
    Groth16ReceiptVerifierParameters, SegmentReceipt, SegmentReceiptVerifierParameters,
    SuccinctReceiptVerifierParameters, VerifierContext,
};
use crate::{
    sha, Assumption, InnerAssumptionReceipt, MaybePruned, Output, PrunedValueError, ReceiptClaim,
};

#[derive(Clone, Debug, Deserialize, Serialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(test, derive(PartialEq))]
#[non_exhaustive]
pub struct CompositeReceipt {

    #[debug("{} segments", segments.len())]
    pub segments: Vec<SegmentReceipt>,

    #[debug("{} assumptions", assumption_receipts.len())]
    pub assumption_receipts: Vec<InnerAssumptionReceipt>,

    pub verifier_parameters: Digest,
}

impl CompositeReceipt {

    // Verifies integrity with context.
    pub fn verify_integrity_with_context(
        &self,
        ctx: &VerifierContext,
    ) -> Result<(), VerificationError> {
        tracing::debug!("CompositeReceipt::verify_integrity_with_context");

        let (final_receipt, receipts) = self
            .segments
            .as_slice()
            .split_last()
            .ok_or(VerificationError::ReceiptFormatError)?;

        let mut expected_pre_state_digest = None;
        for receipt in receipts {
            receipt.verify_integrity_with_context(ctx)?;
            tracing::debug!("claim: {:#?}", receipt.claim);
            if let Some(id) = expected_pre_state_digest {
                if id != receipt.claim.pre.digest::<sha::Impl>() {
                    return Err(VerificationError::ImageVerificationError);
                }
            }
            if receipt.claim.exit_code != ExitCode::SystemSplit {
                return Err(VerificationError::UnexpectedExitCode);
            }
            if !receipt.claim.output.is_none() {
                return Err(VerificationError::ReceiptFormatError);
            }
            expected_pre_state_digest = Some(
                receipt
                    .claim
                    .post
                    .as_value()
                    .map_err(|_| VerificationError::ReceiptFormatError)?
                    .digest::<sha::Impl>(),
            );
        }

        final_receipt.verify_integrity_with_context(ctx)?;
        tracing::debug!("final: {:#?}", final_receipt.claim);
        if let Some(id) = expected_pre_state_digest {
            if id != final_receipt.claim.pre.digest::<sha::Impl>() {
                return Err(VerificationError::ImageVerificationError);
            }
        }

        let assumptions = self.assumptions()?;
        if assumptions.len() != self.assumption_receipts.len() {
            tracing::debug!(
                "only {} receipts provided for {} assumptions",
                assumptions.len(),
                self.assumption_receipts.len()
            );
            return Err(VerificationError::ReceiptFormatError);
        }
        for (assumption, receipt) in assumptions.into_iter().zip(self.assumption_receipts.iter()) {
            let assumption_ctx = match assumption.control_root {

                Digest::ZERO => None,

                control_root => Some(
                    VerifierContext::empty()
                        .with_suites(ctx.suites.clone())
                        .with_succinct_verifier_parameters(SuccinctReceiptVerifierParameters {
                            control_root,
                            inner_control_root: None,
                            proof_system_info: PROOF_SYSTEM_INFO,
                            circuit_info: CircuitImpl::CIRCUIT_INFO,
                        }),
                ),
            };
            tracing::debug!("verifying assumption: {assumption:?}");
            receipt.verify_integrity_with_context(assumption_ctx.as_ref().unwrap_or(ctx))?;
            if receipt.claim_digest()? != assumption.claim {
                tracing::debug!(
                    "verifying assumption failed due to claim mismatch: assumption: {assumption:?}, receipt claim digest: {}",
                    receipt.claim_digest()?
                );
                return Err(VerificationError::ClaimDigestMismatch {
                    expected: assumption.claim,
                    received: receipt.claim_digest()?,
                });
            }
        }

        Ok(())
    }

    // Implements claim.
    pub fn claim(&self) -> Result<ReceiptClaim, VerificationError> {
        let first_claim = &self
            .segments
            .first()
            .ok_or(VerificationError::ReceiptFormatError)?
            .claim;
        let last_claim = &self
            .segments
            .last()
            .ok_or(VerificationError::ReceiptFormatError)?
            .claim;

        let output = last_claim
            .output
            .as_value()
            .map_err(|_| VerificationError::ReceiptFormatError)?
            .as_ref()
            .map(|output| Output {
                journal: output.journal.clone(),
                assumptions: vec![].into(),
            })
            .into();

        Ok(ReceiptClaim {
            pre: first_claim.pre.clone(),
            post: last_claim.post.clone(),
            exit_code: last_claim.exit_code,
            input: first_claim.input.clone(),
            output,
        })
    }

    // Implements assumptions.
    fn assumptions(&self) -> Result<Vec<Assumption>, VerificationError> {

        Ok(self
            .segments
            .last()
            .ok_or(VerificationError::ReceiptFormatError)?
            .claim
            .output
            .as_value()
            .map_err(|_| VerificationError::ReceiptFormatError)?
            .as_ref()
            .map(|output| match output.assumptions.is_empty() {
                true => Ok(Default::default()),
                false => Ok(output
                    .assumptions
                    .as_value()?
                    .iter()
                    .map(|a| a.as_value().cloned())
                    .collect::<Result<_, _>>()?),
            })
            .transpose()
            .map_err(|_: PrunedValueError| VerificationError::ReceiptFormatError)?
            .unwrap_or_default())
    }

    // Implements seal size.
    pub fn seal_size(&self) -> usize {

        let mut result = 0;

        for receipt in &self.segments {
            result += receipt.seal_size();
        }

        for receipt in &self.assumption_receipts {
            result += receipt.seal_size();
        }

        result
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[non_exhaustive]
pub struct CompositeReceiptVerifierParameters {

    pub segment: MaybePruned<SegmentReceiptVerifierParameters>,

    pub succinct: MaybePruned<SuccinctReceiptVerifierParameters>,

    pub groth16: MaybePruned<Groth16ReceiptVerifierParameters>,
}

impl CompositeReceiptVerifierParameters {

    #[stability::unstable]

    // Implements from max po2.
    pub fn from_max_po2(po2_max: usize) -> Self {
        Self {
            segment: MaybePruned::Value(SegmentReceiptVerifierParameters::default()),
            succinct: MaybePruned::Value(SuccinctReceiptVerifierParameters::from_max_po2(po2_max)),
            groth16: MaybePruned::Value(Groth16ReceiptVerifierParameters::from_max_po2(po2_max)),
        }
    }

    #[stability::unstable]

    // Implements all po2s.
    pub fn all_po2s() -> Self {
        Self::from_max_po2(risc0_zkp::MAX_CYCLES_PO2)
    }
}

impl Digestible for CompositeReceiptVerifierParameters {

    // Implements digest.
    fn digest<S: Sha256>(&self) -> Digest {
        tagged_struct::<S>(
            "risc0.CompositeReceiptVerifierParameters",
            &[
                &self.segment.digest::<S>(),
                &self.succinct.digest::<S>(),
                &self.groth16.digest::<S>(),
            ],
            &[],
        )
    }
}

impl Default for CompositeReceiptVerifierParameters {

    // Implements default.
    fn default() -> Self {
        Self {
            segment: MaybePruned::Value(Default::default()),
            succinct: MaybePruned::Value(Default::default()),
            groth16: MaybePruned::Value(Default::default()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CompositeReceiptVerifierParameters;
    use crate::sha::Digestible;
    use risc0_zkp::core::digest::digest;

    #[test]

    // Implements composite receipt verifier parameters is stable.
    fn composite_receipt_verifier_parameters_is_stable() {
        assert_eq!(
            CompositeReceiptVerifierParameters::default().digest(),
            digest!("4bce006e0858edf3a3726987c0b1b6258224c000971e451bc9c05cfec086a84b")
        );
    }
}
