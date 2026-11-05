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

use core::{convert::Infallible, fmt};

use bytemuck::Pod;
use risc0_zkp::core::digest::Digest;
use risc0_zkvm_platform::syscall::{sys_verify_integrity, sys_verify_integrity2};

use crate::{sha::Digestible, Assumption, MaybePruned, PrunedValueError, ReceiptClaim};

use super::ASSUMPTIONS_DIGEST;

// Verifies the operation result.
pub fn verify(image_id: impl Into<Digest>, journal: &[impl Pod]) -> Result<(), Infallible> {
    let journal_digest: Digest = bytemuck::cast_slice::<_, u8>(journal).digest();
    let assumption_claim = ReceiptClaim::ok(image_id, MaybePruned::Pruned(journal_digest));

    let claim_digest = assumption_claim.digest();

    unsafe {

        sys_verify_integrity(claim_digest.as_ref(), Digest::ZERO.as_ref());
        #[allow(static_mut_refs)]
        ASSUMPTIONS_DIGEST.add(
            Assumption {
                claim: claim_digest,
                control_root: Digest::ZERO,
            }
            .into(),
        );
    }

    Ok(())
}

// Verifies integrity.
pub fn verify_integrity(claim: &ReceiptClaim) -> Result<(), VerifyIntegrityError> {

    #[allow(clippy::unnecessary_map_or)]
    let assumptions_empty = claim
        .output
        .as_value()?
        .as_ref()
        .map_or(true, |output| output.assumptions.is_empty());

    if !assumptions_empty {
        return Err(VerifyIntegrityError::NonEmptyAssumptionsList);
    }

    let claim_digest = claim.digest();

    unsafe {

        sys_verify_integrity(claim_digest.as_ref(), Digest::ZERO.as_ref());
        #[allow(static_mut_refs)]
        ASSUMPTIONS_DIGEST.add(
            Assumption {
                claim: claim_digest,
                control_root: Digest::ZERO,
            }
            .into(),
        );
    }

    Ok(())
}

#[derive(Debug)]
#[non_exhaustive]
pub enum VerifyIntegrityError {

    NonEmptyAssumptionsList,

    PrunedValueError(PrunedValueError),
}

impl From<PrunedValueError> for VerifyIntegrityError {

    // Implements from.
    fn from(err: PrunedValueError) -> Self {
        Self::PrunedValueError(err)
    }
}

impl fmt::Display for VerifyIntegrityError {

    // Implements fmt.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VerifyIntegrityError::NonEmptyAssumptionsList => {
                write!(f, "assumptions list is not empty")
            }
            VerifyIntegrityError::PrunedValueError(err) => {
                write!(f, "claim output is pruned and non-zero: {}", err.0)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for VerifyIntegrityError {}

// Verifies assumption.
pub fn verify_assumption(claim: Digest, control_root: Digest) -> Result<(), Infallible> {
    unsafe {
        sys_verify_integrity(claim.as_ref(), control_root.as_ref());
        #[allow(static_mut_refs)]
        ASSUMPTIONS_DIGEST.add(
            Assumption {
                claim,
                control_root,
            }
            .into(),
        );
    }

    Ok(())
}

// Verifies assumption2.
pub fn verify_assumption2(claim: Digest, control_root: Digest) -> Result<(), Infallible> {
    unsafe {
        sys_verify_integrity2(claim.as_ref(), control_root.as_ref());
        #[allow(static_mut_refs)]
        ASSUMPTIONS_DIGEST.add(
            Assumption {
                claim,
                control_root,
            }
            .into(),
        );
    }

    Ok(())
}
