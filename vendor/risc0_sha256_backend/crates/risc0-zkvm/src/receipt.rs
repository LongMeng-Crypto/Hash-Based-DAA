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

//! Manages the output and cryptographic data for a proven computation.

pub(crate) mod composite;
pub(crate) mod groth16;
pub(crate) mod merkle;
pub(crate) mod segment;
pub(crate) mod succinct;

use alloc::{collections::BTreeMap, string::String, vec, vec::Vec};

use anyhow::Result;
use borsh::{BorshDeserialize, BorshSerialize};
use derive_more::Debug;
use risc0_core::field::baby_bear::BabyBear;
use risc0_zkp::{
    core::{
        digest::Digest,
        hash::{
            blake2b::Blake2bCpuHashSuite, poseidon2::Poseidon2HashSuite, sha::Sha256HashSuite,
            HashSuite,
        },
    },
    verify::VerificationError,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    claim::Unknown,
    serde::{from_slice, Error},
    sha::{Digestible, Sha256},
    Assumption, Assumptions, MaybePruned, Output, PrunedValueError, ReceiptClaim,
};

pub use self::groth16::{Groth16Receipt, Groth16ReceiptVerifierParameters};

pub use self::{
    composite::{CompositeReceipt, CompositeReceiptVerifierParameters},
    segment::{SegmentReceipt, SegmentReceiptVerifierParameters},
    succinct::{SuccinctReceipt, SuccinctReceiptVerifierParameters},
};

#[derive(Clone, Debug, Deserialize, Serialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Receipt {

    pub inner: InnerReceipt,

    pub journal: Journal,

    pub metadata: ReceiptMetadata,
}

impl Receipt {

    // Creates the operation result.
    pub fn new(inner: InnerReceipt, journal: Vec<u8>) -> Self {
        let metadata = ReceiptMetadata {
            verifier_parameters: inner.verifier_parameters(),
        };
        Self {
            inner,
            journal: Journal::new(journal),
            metadata,
        }
    }

    // Verifies the operation result.
    pub fn verify(&self, image_id: impl Into<Digest>) -> Result<(), VerificationError> {
        self.verify_with_context(&VerifierContext::default(), image_id)
    }

    // Verifies with context.
    pub fn verify_with_context(
        &self,
        ctx: &VerifierContext,
        image_id: impl Into<Digest>,
    ) -> Result<(), VerificationError> {
        if self.inner.verifier_parameters() != self.metadata.verifier_parameters {

            return Err(VerificationError::ReceiptFormatError);
        }

        tracing::debug!("Receipt::verify_with_context");
        self.inner.verify_integrity_with_context(ctx)?;

        let expected_claim = ReceiptClaim::ok(image_id, MaybePruned::Pruned(self.journal.digest()));
        if expected_claim.digest() != self.inner.claim()?.digest() {
            tracing::debug!(
                "receipt claim does not match expected claim:\nreceipt: {:#?}\nexpected: {:#?}",
                self.inner.claim()?,
                expected_claim
            );
            return Err(VerificationError::ClaimDigestMismatch {
                expected: expected_claim.digest(),
                received: self.claim()?.digest(),
            });
        }

        Ok(())
    }

    // Verifies integrity with context.
    pub fn verify_integrity_with_context(
        &self,
        ctx: &VerifierContext,
    ) -> Result<(), VerificationError> {
        if self.inner.verifier_parameters() != self.metadata.verifier_parameters {

            return Err(VerificationError::ReceiptFormatError);
        }

        tracing::debug!("Receipt::verify_integrity_with_context");
        self.inner.verify_integrity_with_context(ctx)?;

        let maybe_pruned_claim = self.inner.claim()?;
        let claim = maybe_pruned_claim
            .as_value()
            .map_err(|_| VerificationError::ReceiptFormatError)?;

        let expected_output = claim.exit_code.expects_output().then(|| Output {
            journal: MaybePruned::Pruned(self.journal.digest()),

            assumptions: Assumptions(vec![]).into(),
        });

        if claim.output.digest() != expected_output.digest() {
            let empty_output = claim.output.is_none() && self.journal.bytes.is_empty();
            if !empty_output {
                tracing::debug!(
                    "journal: 0x{}, expected output digest: 0x{}, decoded output digest: 0x{}",
                    hex::encode(&self.journal.bytes),
                    hex::encode(expected_output.digest()),
                    hex::encode(claim.output.digest()),
                );
                return Err(VerificationError::JournalDigestMismatch);
            }
            tracing::debug!("accepting zero digest for output of receipt with empty journal");
        }

        Ok(())
    }

    // Implements claim.
    pub fn claim(&self) -> Result<MaybePruned<ReceiptClaim>, VerificationError> {
        self.inner.claim()
    }

    // Implements seal size.
    pub fn seal_size(&self) -> usize {
        self.inner.seal_size()
    }
}

#[derive(
    Clone, Debug, Default, Deserialize, Serialize, PartialEq, BorshSerialize, BorshDeserialize,
)]
pub struct Journal {

    #[debug("{} bytes", bytes.len())]
    pub bytes: Vec<u8>,
}

impl Journal {

    // Creates the operation result.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    // Decodes the operation result.
    pub fn decode<T: DeserializeOwned>(&self) -> Result<T, Error> {
        from_slice(&self.bytes)
    }
}

impl risc0_binfmt::Digestible for Journal {

    // Implements digest.
    fn digest<S: Sha256>(&self) -> Digest {
        *S::hash_bytes(&self.bytes)
    }
}

impl AsRef<[u8]> for Journal {

    // Implements as ref.
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(test, derive(PartialEq))]
#[non_exhaustive]
pub enum InnerReceipt {

    Composite(CompositeReceipt),

    Succinct(SuccinctReceipt<ReceiptClaim>),

    Groth16(Groth16Receipt<ReceiptClaim>),

    Fake(FakeReceipt<ReceiptClaim>),
}

impl InnerReceipt {

    // Verifies integrity.
    pub fn verify_integrity(&self) -> Result<(), VerificationError> {
        self.verify_integrity_with_context(&VerifierContext::default())
    }

    // Verifies integrity with context.
    pub fn verify_integrity_with_context(
        &self,
        ctx: &VerifierContext,
    ) -> Result<(), VerificationError> {
        tracing::debug!("InnerReceipt::verify_integrity_with_context");
        match self {
            Self::Composite(inner) => inner.verify_integrity_with_context(ctx),
            Self::Groth16(inner) => inner.verify_integrity_with_context(ctx),
            Self::Succinct(inner) => inner.verify_integrity_with_context(ctx),
            Self::Fake(inner) => inner.verify_integrity_with_context(ctx),
        }
    }

    // Implements composite.
    pub fn composite(&self) -> Result<&CompositeReceipt, VerificationError> {
        if let Self::Composite(x) = self {
            Ok(x)
        } else {
            Err(VerificationError::ReceiptFormatError)
        }
    }

    // Implements groth16.
    pub fn groth16(&self) -> Result<&Groth16Receipt<ReceiptClaim>, VerificationError> {
        if let Self::Groth16(x) = self {
            Ok(x)
        } else {
            Err(VerificationError::ReceiptFormatError)
        }
    }

    // Implements succinct.
    pub fn succinct(&self) -> Result<&SuccinctReceipt<ReceiptClaim>, VerificationError> {
        if let Self::Succinct(x) = self {
            Ok(x)
        } else {
            Err(VerificationError::ReceiptFormatError)
        }
    }

    // Implements claim.
    pub fn claim(&self) -> Result<MaybePruned<ReceiptClaim>, VerificationError> {
        match self {
            Self::Composite(ref inner) => Ok(inner.claim()?.into()),
            Self::Groth16(ref inner) => Ok(inner.claim.clone()),
            Self::Succinct(ref inner) => Ok(inner.claim.clone()),
            Self::Fake(ref inner) => Ok(inner.claim.clone()),
        }
    }

    // Implements verifier parameters.
    pub fn verifier_parameters(&self) -> Digest {
        match self {
            Self::Composite(ref inner) => inner.verifier_parameters,
            Self::Groth16(ref inner) => inner.verifier_parameters,
            Self::Succinct(ref inner) => inner.verifier_parameters,
            Self::Fake(_) => Digest::ZERO,
        }
    }

    // Implements seal size.
    pub fn seal_size(&self) -> usize {
        match self {
            Self::Composite(receipt) => receipt.seal_size(),
            Self::Succinct(receipt) => receipt.seal_size(),
            Self::Groth16(receipt) => receipt.seal_size(),
            Self::Fake(_) => 0,
        }
    }
}

impl From<CompositeReceipt> for InnerReceipt {

    // Implements from.
    fn from(receipt: CompositeReceipt) -> Self {
        Self::Composite(receipt)
    }
}

impl From<SuccinctReceipt<ReceiptClaim>> for InnerReceipt {

    // Implements from.
    fn from(receipt: SuccinctReceipt<ReceiptClaim>) -> Self {
        Self::Succinct(receipt)
    }
}

impl From<Groth16Receipt<ReceiptClaim>> for InnerReceipt {

    // Implements from.
    fn from(receipt: Groth16Receipt<ReceiptClaim>) -> Self {
        Self::Groth16(receipt)
    }
}

impl From<FakeReceipt<ReceiptClaim>> for InnerReceipt {

    // Implements from.
    fn from(receipt: FakeReceipt<ReceiptClaim>) -> Self {
        Self::Fake(receipt)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(test, derive(PartialEq))]
#[non_exhaustive]
pub enum GenericReceipt<Claim> {

    Succinct(SuccinctReceipt<Claim>),

    Groth16(Groth16Receipt<Claim>),

    Fake(FakeReceipt<Claim>),
}

impl<Claim> GenericReceipt<Claim> {

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
        tracing::debug!("InnerReceipt::verify_integrity_with_context");
        match self {
            Self::Groth16(inner) => inner.verify_integrity_with_context(ctx),
            Self::Succinct(inner) => inner.verify_integrity_with_context(ctx),
            Self::Fake(inner) => inner.verify_integrity_with_context(ctx),
        }
    }

    // Implements groth16.
    pub fn groth16(&self) -> Result<&Groth16Receipt<Claim>, VerificationError> {
        if let Self::Groth16(x) = self {
            Ok(x)
        } else {
            Err(VerificationError::ReceiptFormatError)
        }
    }

    // Implements succinct.
    pub fn succinct(&self) -> Result<&SuccinctReceipt<Claim>, VerificationError> {
        if let Self::Succinct(x) = self {
            Ok(x)
        } else {
            Err(VerificationError::ReceiptFormatError)
        }
    }

    // Implements claim.
    pub fn claim(&self) -> MaybePruned<Claim>
    where
        Claim: Clone,
    {
        match self {
            Self::Groth16(ref inner) => inner.claim.clone(),
            Self::Succinct(ref inner) => inner.claim.clone(),
            Self::Fake(ref inner) => inner.claim.clone(),
        }
    }

    // Implements verifier parameters.
    pub fn verifier_parameters(&self) -> Digest {
        match self {
            Self::Groth16(ref inner) => inner.verifier_parameters,
            Self::Succinct(ref inner) => inner.verifier_parameters,
            Self::Fake(_) => Digest::ZERO,
        }
    }

    // Implements seal size.
    pub fn seal_size(&self) -> usize {
        match self {
            Self::Succinct(receipt) => receipt.seal_size(),
            Self::Groth16(receipt) => receipt.seal_size(),
            Self::Fake(_) => 0,
        }
    }

    // Implements into unknown.
    pub fn into_unknown(self) -> GenericReceipt<Unknown>
    where
        Claim: risc0_binfmt::Digestible,
    {
        match self {
            Self::Succinct(receipt) => receipt.into_unknown().into(),
            Self::Groth16(receipt) => receipt.into_unknown().into(),
            Self::Fake(receipt) => receipt.into_unknown().into(),
        }
    }
}

impl<Claim> From<SuccinctReceipt<Claim>> for GenericReceipt<Claim> {

    // Implements from.
    fn from(receipt: SuccinctReceipt<Claim>) -> Self {
        Self::Succinct(receipt)
    }
}

impl<Claim> From<Groth16Receipt<Claim>> for GenericReceipt<Claim> {

    // Implements from.
    fn from(receipt: Groth16Receipt<Claim>) -> Self {
        Self::Groth16(receipt)
    }
}

impl<Claim> From<FakeReceipt<Claim>> for GenericReceipt<Claim> {

    // Implements from.
    fn from(receipt: FakeReceipt<Claim>) -> Self {
        Self::Fake(receipt)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(test, derive(PartialEq))]
#[non_exhaustive]
pub struct FakeReceipt<Claim> {

    pub claim: MaybePruned<Claim>,
}

impl<Claim> FakeReceipt<Claim> {

    // Creates the operation result.
    pub fn new(claim: impl Into<MaybePruned<Claim>>) -> Self {
        Self {
            claim: claim.into(),
        }
    }

    #[deprecated(note = "Use verify_integrity_with_context instead")]

    // Verifies integrity.
    pub fn verify_integrity(&self) -> Result<(), VerificationError> {
        Err(VerificationError::InvalidProof)
    }

    // Verifies integrity with context.
    pub fn verify_integrity_with_context(
        &self,
        ctx: &VerifierContext,
    ) -> Result<(), VerificationError> {
        if ctx.dev_mode() {
            assert!(cfg!(not(feature = "disable-dev-mode")));
            Ok(())
        } else {
            Err(VerificationError::InvalidProof)
        }
    }

    // Implements into unknown.
    pub fn into_unknown(self) -> FakeReceipt<Unknown>
    where
        Claim: risc0_binfmt::Digestible,
    {
        FakeReceipt {
            claim: MaybePruned::Pruned(self.claim.digest()),
        }
    }
}

impl TryFrom<FakeReceipt<ReceiptClaim>> for Receipt {
    type Error = PrunedValueError;

    // Implements try from.
    fn try_from(fake_receipt: FakeReceipt<ReceiptClaim>) -> Result<Self, Self::Error> {

        let journal = fake_receipt
            .claim
            .as_value()?
            .output
            .as_value()?
            .as_ref()
            .map(|output| Ok(output.journal.as_value()?.clone()))
            .transpose()?
            .unwrap_or_default();
        Ok(Receipt::new(InnerReceipt::Fake(fake_receipt), journal))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, BorshSerialize, BorshDeserialize)]
#[non_exhaustive]
pub struct ReceiptMetadata {

    pub verifier_parameters: Digest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AssumptionReceipt {

    Proven(InnerAssumptionReceipt),

    Unresolved(Assumption),
}

impl AssumptionReceipt {

    // Implements claim digest.
    pub fn claim_digest(&self) -> Result<Digest, VerificationError> {
        match self {
            Self::Proven(receipt) => Ok(receipt.claim_digest()?),
            Self::Unresolved(assumption) => Ok(assumption.claim),
        }
    }
}

impl From<Receipt> for AssumptionReceipt {

    // Implements from.
    fn from(receipt: Receipt) -> Self {
        Self::Proven(receipt.inner.into())
    }
}

impl<Claim> From<GenericReceipt<Claim>> for AssumptionReceipt
where
    Claim: risc0_binfmt::Digestible,
{

    // Implements from.
    fn from(receipt: GenericReceipt<Claim>) -> Self {
        Self::Proven(receipt.into())
    }
}

impl From<InnerReceipt> for AssumptionReceipt {

    // Implements from.
    fn from(receipt: InnerReceipt) -> Self {
        Self::Proven(receipt.into())
    }
}

impl From<InnerAssumptionReceipt> for AssumptionReceipt {

    // Implements from.
    fn from(receipt: InnerAssumptionReceipt) -> Self {
        Self::Proven(receipt)
    }
}

impl<Claim> From<SuccinctReceipt<Claim>> for AssumptionReceipt
where
    Claim: risc0_binfmt::Digestible,
{

    // Implements from.
    fn from(receipt: SuccinctReceipt<Claim>) -> Self {
        Self::Proven(InnerAssumptionReceipt::Succinct(receipt.into_unknown()))
    }
}

impl<Claim> From<FakeReceipt<Claim>> for AssumptionReceipt
where
    Claim: risc0_binfmt::Digestible,
{

    // Implements from.
    fn from(receipt: FakeReceipt<Claim>) -> Self {
        Self::Proven(InnerAssumptionReceipt::Fake(receipt.into_unknown()))
    }
}

impl From<Assumption> for AssumptionReceipt {

    // Implements from.
    fn from(assumption: Assumption) -> Self {
        Self::Unresolved(assumption)
    }
}

impl From<MaybePruned<ReceiptClaim>> for AssumptionReceipt {

    // Implements from.
    fn from(claim: MaybePruned<ReceiptClaim>) -> Self {
        Self::Unresolved(Assumption {
            claim: claim.digest(),
            control_root: Digest::ZERO,
        })
    }
}

impl From<ReceiptClaim> for AssumptionReceipt {

    // Implements from.
    fn from(claim: ReceiptClaim) -> Self {
        Self::Unresolved(Assumption {
            claim: claim.digest(),
            control_root: Digest::ZERO,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(test, derive(PartialEq))]
#[non_exhaustive]
pub enum InnerAssumptionReceipt {

    Composite(CompositeReceipt),

    Succinct(SuccinctReceipt<Unknown>),

    Groth16(Groth16Receipt<Unknown>),

    Fake(FakeReceipt<Unknown>),
}

impl InnerAssumptionReceipt {

    // Verifies integrity with context.
    pub fn verify_integrity_with_context(
        &self,
        ctx: &VerifierContext,
    ) -> Result<(), VerificationError> {
        tracing::debug!("InnerAssumptionReceipt::verify_integrity_with_context");
        match self {
            Self::Composite(inner) => inner.verify_integrity_with_context(ctx),
            Self::Groth16(inner) => inner.verify_integrity_with_context(ctx),
            Self::Succinct(inner) => inner.verify_integrity_with_context(ctx),
            Self::Fake(inner) => inner.verify_integrity_with_context(ctx),
        }
    }

    // Implements composite.
    pub fn composite(&self) -> Result<&CompositeReceipt, VerificationError> {
        if let Self::Composite(x) = self {
            Ok(x)
        } else {
            Err(VerificationError::ReceiptFormatError)
        }
    }

    // Implements groth16.
    pub fn groth16(&self) -> Result<&Groth16Receipt<Unknown>, VerificationError> {
        if let Self::Groth16(x) = self {
            Ok(x)
        } else {
            Err(VerificationError::ReceiptFormatError)
        }
    }

    // Implements succinct.
    pub fn succinct(&self) -> Result<&SuccinctReceipt<Unknown>, VerificationError> {
        if let Self::Succinct(x) = self {
            Ok(x)
        } else {
            Err(VerificationError::ReceiptFormatError)
        }
    }

    // Implements claim digest.
    pub fn claim_digest(&self) -> Result<Digest, VerificationError> {
        match self {
            Self::Composite(ref inner) => Ok(inner.claim()?.digest()),
            Self::Groth16(ref inner) => Ok(inner.claim.digest()),
            Self::Succinct(ref inner) => Ok(inner.claim.digest()),
            Self::Fake(ref inner) => Ok(inner.claim.digest()),
        }
    }

    // Implements verifier parameters.
    pub fn verifier_parameters(&self) -> Digest {
        match self {
            Self::Composite(ref inner) => inner.verifier_parameters,
            Self::Groth16(ref inner) => inner.verifier_parameters,
            Self::Succinct(ref inner) => inner.verifier_parameters,
            Self::Fake(_) => Digest::ZERO,
        }
    }

    // Implements seal size.
    pub fn seal_size(&self) -> usize {
        match self {
            Self::Composite(receipt) => receipt.seal_size(),
            Self::Succinct(receipt) => receipt.seal_size(),
            Self::Groth16(receipt) => receipt.seal_size(),
            Self::Fake(_) => 0,
        }
    }
}

impl From<InnerReceipt> for InnerAssumptionReceipt {

    // Implements from.
    fn from(value: InnerReceipt) -> Self {
        match value {
            InnerReceipt::Composite(x) => InnerAssumptionReceipt::Composite(x),
            InnerReceipt::Succinct(x) => InnerAssumptionReceipt::Succinct(x.into_unknown()),
            InnerReceipt::Groth16(x) => InnerAssumptionReceipt::Groth16(x.into_unknown()),
            InnerReceipt::Fake(x) => InnerAssumptionReceipt::Fake(x.into_unknown()),
        }
    }
}

impl<Claim> From<GenericReceipt<Claim>> for InnerAssumptionReceipt
where
    Claim: risc0_binfmt::Digestible,
{

    // Implements from.
    fn from(value: GenericReceipt<Claim>) -> Self {
        match value {
            GenericReceipt::Succinct(x) => InnerAssumptionReceipt::Succinct(x.into_unknown()),
            GenericReceipt::Groth16(x) => InnerAssumptionReceipt::Groth16(x.into_unknown()),
            GenericReceipt::Fake(x) => InnerAssumptionReceipt::Fake(x.into_unknown()),
        }
    }
}

pub const DEFAULT_MAX_PO2: usize = 22;

#[non_exhaustive]
pub struct VerifierContext {

    pub suites: BTreeMap<String, HashSuite<BabyBear>>,

    pub segment_verifier_parameters: Option<SegmentReceiptVerifierParameters>,

    pub succinct_verifier_parameters: Option<SuccinctReceiptVerifierParameters>,

    pub groth16_verifier_parameters: Option<Groth16ReceiptVerifierParameters>,

    pub(crate) dev_mode: bool,
}

impl VerifierContext {

    // Implements empty.
    pub fn empty() -> Self {
        Self {
            suites: BTreeMap::default(),
            segment_verifier_parameters: None,
            succinct_verifier_parameters: None,
            groth16_verifier_parameters: None,
            dev_mode: crate::is_dev_mode_enabled_via_environment(),
        }
    }

    // Implements default hash suites.
    pub fn default_hash_suites() -> BTreeMap<String, HashSuite<BabyBear>> {
        BTreeMap::from([
            ("blake2b".into(), Blake2bCpuHashSuite::new_suite()),
            ("poseidon2".into(), Poseidon2HashSuite::new_suite()),
            ("sha-256".into(), Sha256HashSuite::new_suite()),
        ])
    }

    #[stability::unstable]

    // Implements from max po2.
    pub fn from_max_po2(po2_max: usize) -> Self {
        Self::from_max_po2_with_hashfn("poseidon2", po2_max).unwrap()
    }

    #[stability::unstable]

    // Implements from max po2 with hashfn.
    pub fn from_max_po2_with_hashfn(hashfn: &str, po2_max: usize) -> anyhow::Result<Self> {
        Ok(Self {
            suites: Self::default_hash_suites(),
            segment_verifier_parameters: Some(SegmentReceiptVerifierParameters::default()),
            succinct_verifier_parameters: Some(
                SuccinctReceiptVerifierParameters::from_max_po2_with_hashfn(hashfn, po2_max)?,
            ),
            groth16_verifier_parameters: Some(Groth16ReceiptVerifierParameters::from_max_po2(
                po2_max,
            )),
            dev_mode: crate::is_dev_mode_enabled_via_environment(),
        })
    }

    // Implements from max po2 with hashfn public.
    pub fn from_max_po2_with_hashfn_public(
        hashfn: &str,
        po2_max: usize,
    ) -> anyhow::Result<Self> {
        Self::from_max_po2_with_hashfn(hashfn, po2_max)
    }

    #[stability::unstable]

    // Implements all po2s.
    pub fn all_po2s() -> Self {
        Self::from_max_po2(risc0_zkp::MAX_CYCLES_PO2)
    }

    // Implements with suites.
    pub fn with_suites(mut self, suites: BTreeMap<String, HashSuite<BabyBear>>) -> Self {
        self.suites = suites;
        self
    }

    // Implements with segment verifier parameters.
    pub fn with_segment_verifier_parameters(
        mut self,
        params: SegmentReceiptVerifierParameters,
    ) -> Self {
        self.segment_verifier_parameters = Some(params);
        self
    }

    // Implements with succinct verifier parameters.
    pub fn with_succinct_verifier_parameters(
        mut self,
        params: SuccinctReceiptVerifierParameters,
    ) -> Self {
        self.succinct_verifier_parameters = Some(params);
        self
    }

    // Implements with groth16 verifier parameters.
    pub fn with_groth16_verifier_parameters(
        mut self,
        params: Groth16ReceiptVerifierParameters,
    ) -> Self {
        self.groth16_verifier_parameters = Some(params);
        self
    }

    // Implements with dev mode.
    pub fn with_dev_mode(mut self, dev_mode: bool) -> Self {
        if cfg!(feature = "disable-dev-mode") && dev_mode {
            panic!("zkVM: Inconsistent settings -- please resolve. \
                The RISC0_DEV_MODE environment variable is set but dev mode has been disabled by feature flag.");
        }
        self.dev_mode = dev_mode;
        self
    }

    // Implements dev mode.
    pub fn dev_mode(&self) -> bool {
        self.dev_mode
    }

    // Implements composite verifier parameters.
    pub fn composite_verifier_parameters(&self) -> Option<CompositeReceiptVerifierParameters> {
        Some(CompositeReceiptVerifierParameters {
            segment: self.segment_verifier_parameters.as_ref()?.clone().into(),
            succinct: self.succinct_verifier_parameters.as_ref()?.clone().into(),
            groth16: self.groth16_verifier_parameters.as_ref()?.clone().into(),
        })
    }
}

impl Default for VerifierContext {

    // Implements default.
    fn default() -> Self {
        Self {
            suites: Self::default_hash_suites(),
            segment_verifier_parameters: Some(Default::default()),
            succinct_verifier_parameters: Some(Default::default()),
            groth16_verifier_parameters: Some(Default::default()),
            dev_mode: crate::is_dev_mode_enabled_via_environment(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{FakeReceipt, InnerReceipt, Receipt};
    use crate::{
        sha::{Digest, DIGEST_BYTES},
        MaybePruned,
    };
    use risc0_zkp::verify::VerificationError;

    #[test]

    // Implements mangled version info should error.
    fn mangled_version_info_should_error() {
        let mut mangled_receipt = Receipt::new(
            InnerReceipt::Fake(FakeReceipt {
                claim: MaybePruned::Pruned(Digest::ZERO),
            }),
            vec![],
        );
        let ones_digest = Digest::from([1u8; DIGEST_BYTES]);
        mangled_receipt.metadata.verifier_parameters = ones_digest;

        assert_eq!(
            mangled_receipt.verify(Digest::ZERO).err().unwrap(),
            VerificationError::ReceiptFormatError
        );
        assert_eq!(
            mangled_receipt
                .verify_with_context(&Default::default(), Digest::ZERO)
                .err()
                .unwrap(),
            VerificationError::ReceiptFormatError
        );
        assert_eq!(
            mangled_receipt
                .verify_integrity_with_context(&Default::default())
                .err()
                .unwrap(),
            VerificationError::ReceiptFormatError
        );
    }

    #[test]

    // Implements borsh serde.
    fn borsh_serde() {
        use crate::ReceiptClaim;
        use risc0_zkvm_methods::MULTI_TEST_ID;

        let claim = ReceiptClaim::ok(MULTI_TEST_ID, vec![]);
        let receipt = Receipt::new(
            InnerReceipt::Fake(FakeReceipt {
                claim: MaybePruned::Value(claim),
            }),
            vec![],
        );
        let encoded = borsh::to_vec(&receipt).unwrap();
        let decoded: Receipt = borsh::from_slice(&encoded).unwrap();
        assert_eq!(receipt, decoded);
    }
}
