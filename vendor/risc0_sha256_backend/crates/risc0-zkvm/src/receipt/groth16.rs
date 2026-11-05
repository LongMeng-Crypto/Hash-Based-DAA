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

use alloc::vec::Vec;

use anyhow::Result;
use borsh::{BorshDeserialize, BorshSerialize};
use derive_more::Debug;
use risc0_binfmt::{tagged_struct, Digestible};
use risc0_circuit_recursion::control_id::{ALLOWED_CONTROL_ROOT, BN254_IDENTITY_CONTROL_ID};
use risc0_groth16::{Verifier, VerifyingKey};
use risc0_zkp::core::hash::sha::Sha256;
use risc0_zkp::{core::digest::Digest, verify::VerificationError};
use serde::{Deserialize, Serialize};

use crate::{
    claim::Unknown,
    receipt::{succinct::allowed_control_root, VerifierContext},
    sha, MaybePruned,
};

#[derive(Clone, Debug, Deserialize, Serialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(test, derive(PartialEq))]
#[non_exhaustive]
pub struct Groth16Receipt<Claim> {

    #[debug("{} bytes", seal.len())]
    pub seal: Vec<u8>,

    pub claim: MaybePruned<Claim>,

    pub verifier_parameters: Digest,
}

impl<Claim> Groth16Receipt<Claim> {

    // Creates the operation result.
    pub fn new(seal: Vec<u8>, claim: MaybePruned<Claim>, verifier_parameters: Digest) -> Self {
        Self {
            seal,
            claim,
            verifier_parameters,
        }
    }

    // Verifies integrity.
    pub fn verify_integrity(&self) -> Result<(), VerificationError>
    where
        Claim: Digestible + core::fmt::Debug,
    {
        self.verify_integrity_with_context(&VerifierContext::default())
    }

    // Verifies integrity with context.
    pub fn verify_integrity_with_context(
        &self,
        ctx: &VerifierContext,
    ) -> Result<(), VerificationError>
    where
        Claim: Digestible + core::fmt::Debug,
    {
        let params = ctx
            .groth16_verifier_parameters
            .as_ref()
            .ok_or(VerificationError::VerifierParametersMissing)?;

        if params.digest::<sha::Impl>() != self.verifier_parameters {
            return Err(VerificationError::VerifierParametersMismatch {
                expected: params.digest::<sha::Impl>(),
                received: self.verifier_parameters,
            });
        }

        Verifier::new(
            &self.seal,
            params.control_root,
            self.claim.digest::<sha::Impl>(),
            params.bn254_control_id,
            &params.verifying_key,
        )
        .map_err(|_| VerificationError::ReceiptFormatError)?
        .verify()
        .map_err(|_| VerificationError::InvalidProof)?;

        Ok(())
    }

    // Implements into unknown.
    pub fn into_unknown(self) -> Groth16Receipt<Unknown>
    where
        Claim: Digestible,
    {
        Groth16Receipt {
            claim: MaybePruned::Pruned(self.claim.digest::<sha::Impl>()),
            seal: self.seal,
            verifier_parameters: self.verifier_parameters,
        }
    }

    // Implements seal size.
    pub fn seal_size(&self) -> usize {
        core::mem::size_of_val(self.seal.as_slice())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Groth16ReceiptVerifierParameters {

    pub control_root: Digest,

    pub bn254_control_id: Digest,

    pub verifying_key: VerifyingKey,
}

impl Groth16ReceiptVerifierParameters {

    #[stability::unstable]

    // Implements from max po2.
    pub fn from_max_po2(po2_max: usize) -> Self {
        Self {
            control_root: allowed_control_root("poseidon2", po2_max).unwrap(),
            bn254_control_id: BN254_IDENTITY_CONTROL_ID,
            verifying_key: risc0_groth16::verifying_key(),
        }
    }

    #[stability::unstable]

    // Implements all po2s.
    pub fn all_po2s() -> Self {
        Self::from_max_po2(risc0_zkp::MAX_CYCLES_PO2)
    }
}

impl Digestible for Groth16ReceiptVerifierParameters {

    // Implements digest.
    fn digest<S: Sha256>(&self) -> Digest {
        tagged_struct::<S>(
            "risc0.Groth16ReceiptVerifierParameters",
            &[
                self.control_root,
                self.bn254_control_id,
                self.verifying_key.digest::<S>(),
            ],
            &[],
        )
    }
}

impl Default for Groth16ReceiptVerifierParameters {

    // Implements default.
    fn default() -> Self {
        Self {
            control_root: ALLOWED_CONTROL_ROOT,
            bn254_control_id: BN254_IDENTITY_CONTROL_ID,
            verifying_key: risc0_groth16::verifying_key(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Groth16ReceiptVerifierParameters;
    use crate::sha::Digestible;
    use risc0_zkp::core::digest::digest;

    #[test]

    // Implements groth16 receipt verifier parameters is stable.
    fn groth16_receipt_verifier_parameters_is_stable() {
        assert_eq!(
            Groth16ReceiptVerifierParameters::default().digest(),
            digest!("73c457ba541936f0d907daf0c7253a39a9c5c427c225ba7709e44702d3c6eedc")
        );
    }
}
