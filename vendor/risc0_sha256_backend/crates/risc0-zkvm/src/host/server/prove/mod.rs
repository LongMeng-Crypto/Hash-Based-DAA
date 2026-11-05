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

//! Run the zkVM guest and prove its results.

pub(crate) mod dev_mode;
pub(crate) mod keccak;
mod prover_impl;
#[cfg(test)]
mod tests;
pub(crate) mod union_peak;

use std::rc::Rc;

use anyhow::{anyhow, bail, ensure, Result};
use risc0_core::field::baby_bear::{BabyBear, Elem, ExtElem};
use risc0_groth16::prove::shrink_wrap;
use risc0_zkp::hal::{CircuitHal, Hal};

use self::{dev_mode::DevModeProver, prover_impl::ProverImpl};
use crate::{
    claim::{receipt::UnionClaim, Unknown},
    host::prove_info::ProveInfo,
    receipt::{
        CompositeReceipt, Groth16Receipt, Groth16ReceiptVerifierParameters, InnerAssumptionReceipt,
        InnerReceipt, SegmentReceipt, SuccinctReceipt,
    },
    sha::Digestible,
    ExecutorEnv, PreflightResults, ProverOpts, Receipt, ReceiptClaim, ReceiptKind, Segment,
    Session, VerifierContext, WorkClaim,
};

mod private {
    use super::{dev_mode::DevModeProver, prover_impl::ProverImpl};

    pub trait Sealed {}
    impl Sealed for ProverImpl {}
    impl Sealed for DevModeProver {}
}

pub trait ProverServer: private::Sealed {

    // Proves the operation result.
    fn prove(&self, env: ExecutorEnv<'_>, elf: &[u8]) -> Result<ProveInfo> {
        self.prove_with_ctx(env, &VerifierContext::default(), elf)
    }

    // Proves with ctx.
    fn prove_with_ctx(
        &self,
        env: ExecutorEnv<'_>,
        ctx: &VerifierContext,
        elf: &[u8],
    ) -> Result<ProveInfo>;

    // Proves session.
    fn prove_session(&self, ctx: &VerifierContext, session: &Session) -> Result<ProveInfo>;

    // Proves segment.
    fn prove_segment(&self, ctx: &VerifierContext, segment: &Segment) -> Result<SegmentReceipt> {
        tracing::debug!("prove_segment");
        let results = self.segment_preflight(segment)?;
        self.prove_segment_core(ctx, results)
    }

    // Implements segment preflight.
    fn segment_preflight(&self, segment: &Segment) -> Result<PreflightResults>;

    // Proves segment core.
    fn prove_segment_core(
        &self,
        ctx: &VerifierContext,
        preflight_results: PreflightResults,
    ) -> Result<SegmentReceipt>;

    // Proves keccak.
    fn prove_keccak(&self, request: &crate::ProveKeccakRequest)
        -> Result<SuccinctReceipt<Unknown>>;

    // Implements lift.
    fn lift(&self, receipt: &SegmentReceipt) -> Result<SuccinctReceipt<ReceiptClaim>>;

    // Implements join.
    fn join(
        &self,
        a: &SuccinctReceipt<ReceiptClaim>,
        b: &SuccinctReceipt<ReceiptClaim>,
    ) -> Result<SuccinctReceipt<ReceiptClaim>>;

    // Implements union.
    fn union(
        &self,
        a: &SuccinctReceipt<Unknown>,
        b: &SuccinctReceipt<Unknown>,
    ) -> Result<SuccinctReceipt<UnionClaim>>;

    // Implements resolve.
    fn resolve(
        &self,
        conditional: &SuccinctReceipt<ReceiptClaim>,
        assumption: &SuccinctReceipt<Unknown>,
    ) -> Result<SuccinctReceipt<ReceiptClaim>>;

    // Implements lift povw.
    fn lift_povw(
        &self,
        receipt: &SegmentReceipt,
    ) -> Result<SuccinctReceipt<WorkClaim<ReceiptClaim>>>;

    // Implements join povw.
    fn join_povw(
        &self,
        a: &SuccinctReceipt<WorkClaim<ReceiptClaim>>,
        b: &SuccinctReceipt<WorkClaim<ReceiptClaim>>,
    ) -> Result<SuccinctReceipt<WorkClaim<ReceiptClaim>>>;

    // Implements join unwrap povw.
    fn join_unwrap_povw(
        &self,
        a: &SuccinctReceipt<WorkClaim<ReceiptClaim>>,
        b: &SuccinctReceipt<WorkClaim<ReceiptClaim>>,
    ) -> Result<SuccinctReceipt<ReceiptClaim>>;

    // Implements resolve povw.
    fn resolve_povw(
        &self,
        conditional: &SuccinctReceipt<WorkClaim<ReceiptClaim>>,
        assumption: &SuccinctReceipt<Unknown>,
    ) -> Result<SuccinctReceipt<WorkClaim<ReceiptClaim>>>;

    // Implements resolve unwrap povw.
    fn resolve_unwrap_povw(
        &self,
        conditional: &SuccinctReceipt<WorkClaim<ReceiptClaim>>,
        assumption: &SuccinctReceipt<Unknown>,
    ) -> Result<SuccinctReceipt<ReceiptClaim>>;

    // Implements unwrap povw.
    fn unwrap_povw(
        &self,
        a: &SuccinctReceipt<WorkClaim<ReceiptClaim>>,
    ) -> Result<SuccinctReceipt<ReceiptClaim>>;

    // Implements identity p254.
    fn identity_p254(
        &self,
        a: &SuccinctReceipt<ReceiptClaim>,
    ) -> Result<SuccinctReceipt<ReceiptClaim>>;

    // Implements composite to succinct.
    fn composite_to_succinct(
        &self,
        receipt: &CompositeReceipt,
    ) -> Result<SuccinctReceipt<ReceiptClaim>> {
        <Self as Compress<_>>::composite_to_succinct(self, receipt)
    }

    // Implements composite to succinct povw.
    fn composite_to_succinct_povw(
        &self,
        receipt: &CompositeReceipt,
    ) -> Result<SuccinctReceipt<WorkClaim<ReceiptClaim>>> {
        <Self as Compress<_>>::composite_to_succinct(self, receipt)
    }

    // Implements succinct to groth16.
    fn succinct_to_groth16(
        &self,
        receipt: &SuccinctReceipt<ReceiptClaim>,
    ) -> Result<Groth16Receipt<ReceiptClaim>> {
        let ident_receipt = self.identity_p254(receipt).unwrap();
        let seal_bytes = ident_receipt.get_seal_bytes();
        let seal = shrink_wrap(&seal_bytes)?.to_vec();
        Ok(Groth16Receipt {
            seal,
            claim: receipt.claim.clone(),
            verifier_parameters: Groth16ReceiptVerifierParameters::default().digest(),
        })
    }

    // Implements compress.
    fn compress(&self, opts: &ProverOpts, receipt: &Receipt) -> Result<Receipt> {
        match &receipt.inner {
            InnerReceipt::Composite(inner) => match opts.receipt_kind {
                ReceiptKind::Composite => Ok(receipt.clone()),
                ReceiptKind::Succinct => {
                    let succinct_receipt = self.composite_to_succinct(inner)?;
                    Ok(Receipt::new(
                        InnerReceipt::Succinct(succinct_receipt),
                        receipt.journal.bytes.clone(),
                    ))
                }
                ReceiptKind::Groth16 => {
                    let succinct_receipt = self.composite_to_succinct(inner)?;
                    let groth16_receipt = self.succinct_to_groth16(&succinct_receipt)?;
                    Ok(Receipt::new(
                        InnerReceipt::Groth16(groth16_receipt),
                        receipt.journal.bytes.clone(),
                    ))
                }
            },
            InnerReceipt::Succinct(inner) => match opts.receipt_kind {
                ReceiptKind::Composite | ReceiptKind::Succinct => Ok(receipt.clone()),
                ReceiptKind::Groth16 => {
                    let groth16_receipt = self.succinct_to_groth16(inner)?;
                    Ok(Receipt::new(
                        InnerReceipt::Groth16(groth16_receipt),
                        receipt.journal.bytes.clone(),
                    ))
                }
            },
            InnerReceipt::Groth16(_) => match opts.receipt_kind {
                ReceiptKind::Composite | ReceiptKind::Succinct | ReceiptKind::Groth16 => {
                    Ok(receipt.clone())
                }
            },
            InnerReceipt::Fake(_) => {
                ensure!(
                    opts.dev_mode(),
                    "dev mode must be enabled to compress fake receipts"
                );
                Ok(receipt.clone())
            }
        }
    }
}

trait Lift<Claim> {

    // Implements lift.
    fn lift(&self, segment_receipt: &SegmentReceipt) -> anyhow::Result<SuccinctReceipt<Claim>>;
}

impl<P: ProverServer + ?Sized> Lift<ReceiptClaim> for P {

    // Implements lift.
    fn lift(
        &self,
        segment_receipt: &SegmentReceipt,
    ) -> anyhow::Result<SuccinctReceipt<ReceiptClaim>> {
        <Self as ProverServer>::lift(self, segment_receipt)
    }
}

impl<P: ProverServer + ?Sized> Lift<WorkClaim<ReceiptClaim>> for P {

    // Implements lift.
    fn lift(
        &self,
        segment_receipt: &SegmentReceipt,
    ) -> anyhow::Result<SuccinctReceipt<WorkClaim<ReceiptClaim>>> {
        self.lift_povw(segment_receipt)
    }
}

trait Join<Claim> {

    // Implements join.
    fn join(
        &self,
        a: &SuccinctReceipt<Claim>,
        b: &SuccinctReceipt<Claim>,
    ) -> anyhow::Result<SuccinctReceipt<Claim>>;
}

impl<P: ProverServer + ?Sized> Join<ReceiptClaim> for P {

    // Implements join.
    fn join(
        &self,
        a: &SuccinctReceipt<ReceiptClaim>,
        b: &SuccinctReceipt<ReceiptClaim>,
    ) -> anyhow::Result<SuccinctReceipt<ReceiptClaim>> {
        <Self as ProverServer>::join(self, a, b)
    }
}

impl<P: ProverServer + ?Sized> Join<WorkClaim<ReceiptClaim>> for P {

    // Implements join.
    fn join(
        &self,
        a: &SuccinctReceipt<WorkClaim<ReceiptClaim>>,
        b: &SuccinctReceipt<WorkClaim<ReceiptClaim>>,
    ) -> anyhow::Result<SuccinctReceipt<WorkClaim<ReceiptClaim>>> {
        self.join_povw(a, b)
    }
}

trait Resolve<Claim> {

    // Implements resolve.
    fn resolve(
        &self,
        cond: &SuccinctReceipt<Claim>,
        assum: &SuccinctReceipt<Unknown>,
    ) -> anyhow::Result<SuccinctReceipt<Claim>>;
}

impl<P: ProverServer + ?Sized> Resolve<ReceiptClaim> for P {

    // Implements resolve.
    fn resolve(
        &self,
        cond: &SuccinctReceipt<ReceiptClaim>,
        assum: &SuccinctReceipt<Unknown>,
    ) -> anyhow::Result<SuccinctReceipt<ReceiptClaim>> {
        <Self as ProverServer>::resolve(self, cond, assum)
    }
}

impl<P: ProverServer + ?Sized> Resolve<WorkClaim<ReceiptClaim>> for P {

    // Implements resolve.
    fn resolve(
        &self,
        cond: &SuccinctReceipt<WorkClaim<ReceiptClaim>>,
        assum: &SuccinctReceipt<Unknown>,
    ) -> anyhow::Result<SuccinctReceipt<WorkClaim<ReceiptClaim>>> {
        self.resolve_povw(cond, assum)
    }
}

trait Compress<Claim> {

    // Implements composite to succinct.
    fn composite_to_succinct(
        &self,
        composite_receipt: &CompositeReceipt,
    ) -> anyhow::Result<SuccinctReceipt<Claim>>;
}

impl<P, Claim> Compress<Claim> for P
where
    P: Lift<Claim>
        + Join<Claim>
        + Resolve<Claim>
        + Lift<ReceiptClaim>
        + Join<ReceiptClaim>
        + Resolve<ReceiptClaim>
        + ?Sized,
{

    // Implements composite to succinct.
    fn composite_to_succinct(
        &self,
        composite_receipt: &CompositeReceipt,
    ) -> anyhow::Result<SuccinctReceipt<Claim>> {

        let continuation_receipt = composite_receipt
            .segments
            .iter()
            .try_fold(
                None,
                |left: Option<SuccinctReceipt<Claim>>, right: &SegmentReceipt| -> Result<_> {
                    Ok(Some(match left {
                        Some(left) => self.join(&left, &self.lift(right)?)?,
                        None => self.lift(right)?,
                    }))
                },
            )?
            .ok_or_else(|| {
                anyhow!("malformed composite receipt has no continuation segment receipts")
            })?;

        composite_receipt.assumption_receipts.iter().try_fold(
            continuation_receipt,
            |conditional: SuccinctReceipt<Claim>, assumption: &InnerAssumptionReceipt| match assumption {
                InnerAssumptionReceipt::Succinct(assumption) => self.resolve(&conditional, assumption),
                InnerAssumptionReceipt::Composite(assumption) => {
                    self.resolve(&conditional, &SuccinctReceipt::<ReceiptClaim>::into_unknown(self.composite_to_succinct(assumption)?))
                }
                InnerAssumptionReceipt::Fake(_) => bail!(
                    "compressing composite receipts with fake receipt assumptions is not supported"
                ),
                InnerAssumptionReceipt::Groth16(_) => bail!(
                    "compressing composite receipts with Groth16 receipt assumptions is not supported"
                )
            },
        )
    }
}

#[derive(Clone)]
pub struct HalPair<H, C>
where
    H: Hal<Field = BabyBear, Elem = Elem, ExtElem = ExtElem>,
    C: CircuitHal<H>,
{

    pub hal: Rc<H>,

    pub circuit_hal: Rc<C>,
}

impl Session {

    // Proves the operation result.
    pub fn prove(&self) -> Result<ProveInfo> {
        let prover = get_prover_server(&ProverOpts::default())?;
        prover.prove_session(&VerifierContext::default(), self)
    }
}

// Returns prover server.
pub fn get_prover_server(opts: &ProverOpts) -> Result<Rc<dyn ProverServer>> {
    if opts.dev_mode() {
        eprintln!("WARNING: proving in dev mode. This will not generate valid, secure proofs.");
        return Ok(Rc::new(DevModeProver::new()));
    }

    Ok(Rc::new(ProverImpl::new(opts.clone())))
}
