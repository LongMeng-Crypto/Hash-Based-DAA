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

//! [ReceiptClaim] and associated types and functions.
//!
//! A [ReceiptClaim] struct contains the public claims (i.e. public outputs) of a zkVM guest
//! execution, such as the journal committed to by the guest. It also includes important
//! information such as the exit code and the starting and ending system state (i.e. the state of
//! memory).

use alloc::{collections::VecDeque, vec::Vec};
use core::{fmt, ops::Deref};

#[cfg(feature = "std")]
use anyhow::Context;
use anyhow::{anyhow, bail, ensure};
use borsh::{BorshDeserialize, BorshSerialize};
use derive_more::Debug;
use risc0_binfmt::{
    read_sha_halfs, tagged_list, tagged_list_cons, tagged_struct, write_sha_halfs, Digestible,
    ExitCode, InvalidExitCodeError,
};
use risc0_circuit_rv32im::{HighLowU16, Rv32imV2Claim, TerminateState};
use risc0_zkp::core::digest::Digest;
use risc0_zkvm_platform::syscall::halt;
use serde::{Deserialize, Serialize};

use super::{
    maybe_pruned::{MaybePruned, PrunedValueError},
    work::WorkClaimError,
    Unknown,
};
use crate::{
    sha::{self, Sha256},
    SystemState, WorkClaim,
};

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ReceiptClaim {

    pub pre: MaybePruned<SystemState>,

    pub post: MaybePruned<SystemState>,

    pub exit_code: ExitCode,

    pub input: MaybePruned<Option<Input>>,

    pub output: MaybePruned<Option<Output>>,
}

impl ReceiptClaim {

    // Implements ok.
    pub fn ok(
        image_id: impl Into<Digest>,
        journal: impl Into<MaybePruned<Vec<u8>>>,
    ) -> ReceiptClaim {
        Self {
            pre: MaybePruned::Pruned(image_id.into()),
            post: MaybePruned::Value(SystemState {
                pc: 0,
                merkle_root: Digest::ZERO,
            }),
            exit_code: ExitCode::Halted(0),
            input: None.into(),
            output: Some(Output {
                journal: journal.into(),
                assumptions: MaybePruned::Pruned(Digest::ZERO),
            })
            .into(),
        }
    }

    // Implements paused.
    pub fn paused(
        image_id: impl Into<Digest>,
        journal: impl Into<MaybePruned<Vec<u8>>>,
    ) -> ReceiptClaim {
        Self {
            pre: MaybePruned::Pruned(image_id.into()),
            post: MaybePruned::Value(SystemState {
                pc: 0,
                merkle_root: Digest::ZERO,
            }),
            exit_code: ExitCode::Paused(0),
            input: None.into(),
            output: Some(Output {
                journal: journal.into(),
                assumptions: MaybePruned::Pruned(Digest::ZERO),
            })
            .into(),
        }
    }

    // Decodes the operation result.
    pub fn decode(flat: &mut VecDeque<u32>) -> Result<Self, DecodeError> {
        let input = read_sha_halfs(flat)?;
        let pre = SystemState::decode(flat)?;
        let post = SystemState::decode(flat)?;
        let sys_exit = flat
            .pop_front()
            .ok_or(risc0_binfmt::DecodeError::EndOfStream)?;
        let user_exit = flat
            .pop_front()
            .ok_or(risc0_binfmt::DecodeError::EndOfStream)?;
        let exit_code = ExitCode::from_pair(sys_exit, user_exit)?;
        let output = read_sha_halfs(flat)?;

        Ok(Self {
            input: MaybePruned::Pruned(input),
            pre: pre.into(),
            post: post.into(),
            exit_code,
            output: MaybePruned::Pruned(output),
        })
    }

    // Encodes the operation result.
    pub fn encode(&self, flat: &mut Vec<u32>) -> Result<(), PrunedValueError> {
        write_sha_halfs(flat, &self.input.digest::<sha::Impl>());
        self.pre.as_value()?.encode(flat);
        self.post.as_value()?.encode(flat);
        let (sys_exit, user_exit) = self.exit_code.into_pair();
        flat.push(sys_exit);
        flat.push(user_exit);
        write_sha_halfs(flat, &self.output.digest::<sha::Impl>());
        Ok(())
    }

    // Decodes from seal v2.
    pub(crate) fn decode_from_seal_v2(
        seal: &[u32],
        _po2: Option<u32>,
    ) -> anyhow::Result<ReceiptClaim> {
        let claim = Rv32imV2Claim::decode(seal)?;
        tracing::debug!("claim: {claim:#?}");

        let exit_code = exit_code_from_terminate_state(&claim.terminate_state)?;
        let post_state = match exit_code {
            ExitCode::Halted(_) => Digest::ZERO,
            _ => claim.post_state,
        };

        Ok(ReceiptClaim {
            pre: MaybePruned::Value(SystemState {
                pc: 0,
                merkle_root: claim.pre_state,
            }),
            post: MaybePruned::Value(SystemState {
                pc: 0,
                merkle_root: post_state,
            }),
            exit_code,
            input: MaybePruned::Pruned(claim.input),
            output: MaybePruned::Pruned(claim.output.unwrap_or_default()),
        })
    }

    // Implements join.
    pub fn join(&self, other: &Self) -> Self {
        ReceiptClaim {
            pre: self.pre.clone(),
            post: other.post.clone(),
            exit_code: other.exit_code,
            input: self.input.clone(),
            output: other.output.clone(),
        }
    }

    #[cfg(feature = "std")]

    // Implements resolve.
    pub fn resolve<Claim: risc0_binfmt::Digestible + ?Sized>(
        &self,
        assumption: &Claim,
    ) -> anyhow::Result<Self> {
        let mut resolved_claim = self.clone();

        let assumptions: &mut Assumptions = resolved_claim
            .output
            .as_value_mut()
            .context("conditional receipt output is pruned")?
            .as_mut()
            .ok_or_else(|| anyhow!("conditional receipt has empty output and no assumptions"))?
            .assumptions
            .as_value_mut()
            .context("conditional receipt has pruned assumptions")?;

        let head_control_root = assumptions
            .first()
            .context("assumptions list is empty")?
            .as_value()?
            .control_root;

        assumptions.resolve(
            &Assumption {
                control_root: head_control_root,
                claim: assumption.digest::<sha::Impl>(),
            }
            .digest::<sha::Impl>(),
        )?;

        Ok(resolved_claim)
    }
}

impl MaybePruned<ReceiptClaim> {

    // Implements join.
    pub fn join(&self, other: &Self) -> Result<Self, PrunedValueError> {
        Ok(self.as_value()?.join(other.as_value()?).into())
    }

    #[cfg(feature = "std")]

    // Implements resolve.
    pub fn resolve<Claim: risc0_binfmt::Digestible + ?Sized>(
        &self,
        assumption: &Claim,
    ) -> anyhow::Result<Self> {
        Ok(self
            .as_value()
            .context("conditional claim is pruned")?
            .resolve(assumption)?
            .into())
    }
}

impl WorkClaim<ReceiptClaim> {

    // Implements join.
    pub fn join(&self, other: &Self) -> Result<Self, WorkClaimError> {
        Ok(Self {
            claim: self.claim.join(&other.claim)?,
            work: self.work.join(&other.work)?,
        })
    }

    #[cfg(feature = "std")]

    // Implements resolve.
    pub fn resolve<Claim: risc0_binfmt::Digestible + ?Sized>(
        &self,
        assumption: &Claim,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            claim: self.claim.resolve(assumption)?,
            work: self.work.clone(),
        })
    }
}

impl MaybePruned<WorkClaim<ReceiptClaim>> {

    // Implements join.
    pub fn join(&self, other: &Self) -> Result<Self, WorkClaimError> {
        Ok(self.as_value()?.join(other.as_value()?)?.into())
    }

    #[cfg(feature = "std")]

    // Implements resolve.
    pub fn resolve<Claim: risc0_binfmt::Digestible + ?Sized>(
        &self,
        assumption: &Claim,
    ) -> anyhow::Result<Self> {
        Ok(self
            .as_value()
            .context("conditional povw claim is pruned")?
            .resolve(assumption)?
            .into())
    }
}

// Implements exit code from terminate state.
pub(crate) fn exit_code_from_terminate_state(
    terminate_state: &Option<TerminateState>,
) -> anyhow::Result<ExitCode> {
    let exit_code = if let Some(term) = terminate_state {
        let HighLowU16(user_exit, halt_type) = term.a0;
        match halt_type as u32 {
            halt::TERMINATE => ExitCode::Halted(user_exit as u32),
            halt::PAUSE => ExitCode::Paused(user_exit as u32),
            _ => bail!("Illegal halt type: {halt_type}"),
        }
    } else {
        ExitCode::SystemSplit
    };
    Ok(exit_code)
}

impl Digestible for ReceiptClaim {

    // Implements digest.
    fn digest<S: Sha256>(&self) -> Digest {
        let (sys_exit, user_exit) = self.exit_code.into_pair();
        tagged_struct::<S>(
            "risc0.ReceiptClaim",
            &[
                self.input.digest::<S>(),
                self.pre.digest::<S>(),
                self.post.digest::<S>(),
                self.output.digest::<S>(),
            ],
            &[sys_exit, user_exit],
        )
    }
}

#[derive(Debug, Copy, Clone)]
pub enum DecodeError {

    InvalidExitCode(InvalidExitCodeError),

    Decode(risc0_binfmt::DecodeError),
}

impl fmt::Display for DecodeError {

    // Implements fmt.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InvalidExitCode(e) => write!(f, "failed to decode receipt claim: {e}"),
            Self::Decode(e) => write!(f, "failed to decode receipt claim: {e}"),
        }
    }
}

impl From<risc0_binfmt::DecodeError> for DecodeError {

    // Implements from.
    fn from(e: risc0_binfmt::DecodeError) -> Self {
        Self::Decode(e)
    }
}

impl From<InvalidExitCodeError> for DecodeError {

    // Implements from.
    fn from(e: InvalidExitCodeError) -> Self {
        Self::InvalidExitCode(e)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecodeError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnionClaim {

    pub left: Digest,

    pub right: Digest,
}

impl Digestible for UnionClaim {

    // Implements digest.
    fn digest<S: Sha256>(&self) -> Digest {
        tagged_struct::<S>("risc0.UnionClaim", &[self.left, self.right], &[])
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Input {

    pub(crate) x: Unknown,
}

impl Digestible for Input {

    // Implements digest.
    fn digest<S: Sha256>(&self) -> Digest {
        match self.x {   }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Output {

    #[debug("{}", fmt_debug_journal(journal))]
    pub journal: MaybePruned<Vec<u8>>,

    pub assumptions: MaybePruned<Assumptions>,
}

#[allow(dead_code)]

// Implements fmt debug journal.
fn fmt_debug_journal(journal: &MaybePruned<Vec<u8>>) -> alloc::string::String {
    match journal {
        MaybePruned::Value(bytes) => alloc::format!("{} bytes", bytes.len()),
        MaybePruned::Pruned(_) => alloc::format!("{journal:?}"),
    }
}

impl Digestible for Output {

    // Implements digest.
    fn digest<S: Sha256>(&self) -> Digest {
        tagged_struct::<S>(
            "risc0.Output",
            &[self.journal.digest::<S>(), self.assumptions.digest::<S>()],
            &[],
        )
    }
}

#[derive(
    Clone, Debug, Serialize, Deserialize, Eq, Hash, PartialEq, BorshSerialize, BorshDeserialize,
)]
pub struct Assumption {

    pub claim: Digest,

    pub control_root: Digest,
}

impl Digestible for Assumption {

    // Implements digest.
    fn digest<S: Sha256>(&self) -> Digest {
        tagged_struct::<S>("risc0.Assumption", &[self.claim, self.control_root], &[])
    }
}

#[derive(Clone, Default, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Assumptions(pub Vec<MaybePruned<Assumption>>);

impl Assumptions {

    // Adds the operation result.
    pub fn add(&mut self, assumption: MaybePruned<Assumption>) {
        self.0.insert(0, assumption);
    }

    // Implements resolve.
    pub fn resolve(&mut self, resolved: &Digest) -> anyhow::Result<()> {
        let head = self
            .0
            .first()
            .ok_or_else(|| anyhow!("cannot resolve assumption from empty list"))?;

        ensure!(
            &head.digest::<sha::Impl>() == resolved,
            "resolved assumption is not equal to the head of the list: {} != {}",
            resolved,
            head.digest::<sha::Impl>()
        );

        self.0 = self.0.split_off(1);
        Ok(())
    }
}

impl Deref for Assumptions {
    type Target = [MaybePruned<Assumption>];

    // Implements deref.
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Digestible for Assumptions {

    // Implements digest.
    fn digest<S: Sha256>(&self) -> Digest {
        tagged_list::<S>(
            "risc0.Assumptions",
            &self.0.iter().map(|a| a.digest::<S>()).collect::<Vec<_>>(),
        )
    }
}

impl MaybePruned<Assumptions> {

    // Checks empty.
    pub fn is_empty(&self) -> bool {
        match self {
            MaybePruned::Value(list) => list.is_empty(),
            MaybePruned::Pruned(digest) => digest == &Digest::ZERO,
        }
    }

    // Adds the operation result.
    pub fn add(&mut self, assumption: MaybePruned<Assumption>) {
        match self {
            MaybePruned::Value(list) => list.add(assumption),
            MaybePruned::Pruned(list_digest) => {
                *list_digest = tagged_list_cons::<sha::Impl>(
                    "risc0.Assumptions",
                    &assumption.digest::<sha::Impl>(),
                    &*list_digest,
                );
            }
        }
    }

    // Implements resolve.
    pub fn resolve(&mut self, resolved: &Digest, tail: &Digest) -> anyhow::Result<()> {
        match self {
            MaybePruned::Value(list) => list.resolve(resolved),
            MaybePruned::Pruned(list_digest) => {
                let reconstructed =
                    tagged_list_cons::<sha::Impl>("risc0.Assumptions", resolved, tail);
                ensure!(
                    &reconstructed == list_digest,
                    "reconstructed list digest does not match; expected {}, reconstructed {}",
                    list_digest,
                    reconstructed
                );

                *list_digest = *tail;
                Ok(())
            }
        }
    }
}

impl From<Vec<MaybePruned<Assumption>>> for Assumptions {

    // Implements from.
    fn from(value: Vec<MaybePruned<Assumption>>) -> Self {
        Self(value)
    }
}

impl From<Vec<Assumption>> for Assumptions {

    // Implements from.
    fn from(value: Vec<Assumption>) -> Self {
        Self(value.into_iter().map(Into::into).collect())
    }
}

impl From<Vec<Assumption>> for MaybePruned<Assumptions> {

    // Implements from.
    fn from(value: Vec<Assumption>) -> Self {
        Self::Value(value.into())
    }
}
