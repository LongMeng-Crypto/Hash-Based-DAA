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

//! [WorkClaim] and associated types and functions.

use alloc::{boxed::Box, collections::VecDeque, vec::Vec};
use core::fmt;

use borsh::{BorshDeserialize, BorshSerialize};
use risc0_binfmt::{tagged_struct, DecodeError, Digestible, PovwNonce};
use serde::{Deserialize, Serialize};

use crate::{
    sha,
    sha::{Digest, Sha256},
    MaybePruned, PrunedValueError, ReceiptClaim, Unknown,
};

#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct WorkClaim<Claim> {

    pub claim: MaybePruned<Claim>,

    pub work: MaybePruned<Work>,
}

impl<Claim> WorkClaim<Claim> {

    // Implements into unknown.
    pub fn into_unknown(self) -> WorkClaim<Unknown>
    where
        Claim: Digestible,
    {
        WorkClaim {
            claim: MaybePruned::Pruned(self.claim.digest::<sha::Impl>()),
            work: self.work,
        }
    }
}

impl<Claim> Digestible for WorkClaim<Claim>
where
    Claim: Digestible,
{

    // Implements digest.
    fn digest<S: Sha256>(&self) -> Digest {
        tagged_struct::<S>(
            "risc0.WorkClaim",
            &[self.claim.digest::<S>(), self.work.digest::<S>()],
            &[],
        )
    }
}

impl<Claim> fmt::Debug for WorkClaim<Claim>
where
    Claim: Digestible + fmt::Debug,
{

    // Implements fmt.
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("WorkClaim")
            .field("claim", &self.claim)
            .field("work", &self.work)
            .finish()
    }
}

impl WorkClaim<ReceiptClaim> {

    // Encodes to seal.
    pub fn encode_to_seal(&self, buf: &mut Vec<u32>) -> Result<(), PrunedValueError> {
        self.claim.as_value()?.encode(buf)?;
        self.work.as_value()?.encode_to_seal(buf);
        Ok(())
    }

    // Decodes from seal.
    pub fn decode_from_seal(
        buf: &mut VecDeque<u32>,
    ) -> Result<Self, crate::claim::receipt::DecodeError> {
        Ok(Self {
            claim: ReceiptClaim::decode(buf)?.into(),
            work: Work::decode_from_seal(buf)?.into(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct Work {

    pub nonce_min: PovwNonce,

    pub nonce_max: PovwNonce,

    pub value: u64,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum WorkClaimError {
    NonceRangesNotContiguous(Box<(Work, Work)>),
    PrunedValue(PrunedValueError),
}

impl fmt::Display for WorkClaimError {

    // Implements fmt.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            WorkClaimError::NonceRangesNotContiguous(ab) => {
                write!(
                    f,
                    "work nonce ranges are not contiguous: ({:?}, {:?}) and ({:?}. {:?})",
                    ab.0.nonce_min, ab.0.nonce_max, ab.1.nonce_min, ab.1.nonce_max
                )
            }
            WorkClaimError::PrunedValue(err) => err.fmt(f),
        }
    }
}

impl From<PrunedValueError> for WorkClaimError {

    // Implements from.
    fn from(err: PrunedValueError) -> Self {
        Self::PrunedValue(err)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for WorkClaimError {}

impl Work {

    // Implements join.
    pub fn join(&self, other: &Self) -> Result<Self, WorkClaimError> {

        let contiguous = self
            .nonce_max
            .to_u256()
            .checked_add(1u64.try_into().unwrap())
            .map(|max| max == other.nonce_min.to_u256())
            .unwrap_or(false);
        if !contiguous {
            return Err(WorkClaimError::NonceRangesNotContiguous(Box::new((
                self.clone(),
                other.clone(),
            ))));
        }

        Ok(Self {
            nonce_min: self.nonce_min,
            nonce_max: other.nonce_max,
            value: self.value + other.value,
        })
    }

    // Encodes to seal.
    pub(crate) fn encode_to_seal(&self, buf: &mut Vec<u32>) {
        buf.extend(self.nonce_min.to_u16s().into_iter().map(u32::from));
        buf.extend(self.nonce_max.to_u16s().into_iter().map(u32::from));
        buf.extend(u64_to_u16s(self.value).into_iter().map(u32::from));
    }

    // Decodes from seal.
    pub(crate) fn decode_from_seal(
        buf: &mut VecDeque<u32>,
    ) -> Result<Self, risc0_binfmt::DecodeError> {
        Ok(Self {
            nonce_min: PovwNonce::decode_from_seal(buf)?,
            nonce_max: PovwNonce::decode_from_seal(buf)?,
            value: decode_work_value_from_seal(buf)?,
        })
    }
}

impl MaybePruned<Work> {

    // Implements join.
    pub fn join(&self, other: &Self) -> Result<Self, WorkClaimError> {
        Ok(self.as_value()?.join(other.as_value()?)?.into())
    }
}

// Implements u64 to u16s.
fn u64_to_u16s(x: u64) -> [u16; 4] {
    let mut u16s = bytemuck::cast::<_, [u16; 4]>(x.to_le_bytes());

    for x in u16s.iter_mut() {
        *x = u16::from_le(*x);
    }
    u16s
}

// Implements u64 from u16s.
fn u64_from_u16s(mut u16s: [u16; 4]) -> u64 {

    for x in u16s.iter_mut() {
        *x = u16::from_le(*x);
    }
    u64::from_le_bytes(bytemuck::cast(u16s))
}

// Decodes work value from seal.
fn decode_work_value_from_seal(buf: &mut VecDeque<u32>) -> Result<u64, risc0_binfmt::DecodeError> {
    if buf.len() < 4 {
        return Err(DecodeError::EndOfStream);
    }

    // Implements u16 from u32.
    fn u16_from_u32(x: u32) -> Result<u16, risc0_binfmt::DecodeError> {
        x.try_into()
            .map_err(|_| risc0_binfmt::DecodeError::OutOfRange)
    }
    Ok(u64_from_u16s(
        buf.drain(..4)
            .map(u16_from_u32)
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .unwrap(),
    ))
}

impl Digestible for Work {

    // Implements digest.
    fn digest<S: Sha256>(&self) -> Digest {
        let mut buf = Vec::new();
        self.encode_to_seal(&mut buf);
        tagged_struct::<S>("risc0.Work", &Vec::<Digest>::new(), &buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{sha, ReceiptClaim};
    use alloc::collections::VecDeque;
    use risc0_binfmt::{ExitCode, SystemState};

    #[test]

    // Tests work seal encoding round trip.
    fn test_work_seal_encoding_round_trip() {
        let original = Work {
            nonce_min: rand::random(),
            nonce_max: rand::random(),
            value: rand::random(),
        };

        let mut buf = Vec::new();
        original.encode_to_seal(&mut buf);

        let mut decode_buf = VecDeque::from(buf);
        let decoded = Work::decode_from_seal(&mut decode_buf).unwrap();

        assert_eq!(original.nonce_min, decoded.nonce_min);
        assert_eq!(original.nonce_max, decoded.nonce_max);
        assert_eq!(original.value, decoded.value);
        assert!(decode_buf.is_empty());
    }

    #[test]

    // Tests work claim seal encoding round trip.
    fn test_work_claim_seal_encoding_round_trip() {
        use crate::sha::Digest;

        let claim = ReceiptClaim {
            pre: SystemState {
                pc: 0,
                merkle_root: *sha::Impl::hash_bytes(b"pre"),
            }
            .into(),
            post: SystemState {
                pc: 0,
                merkle_root: *sha::Impl::hash_bytes(b"pre"),
            }
            .into(),
            output: MaybePruned::Pruned(Digest::ZERO),
            input: MaybePruned::Pruned(Digest::ZERO),
            exit_code: ExitCode::SystemSplit,
        };

        let original = WorkClaim {
            claim: claim.into(),
            work: Work {
                nonce_min: rand::random(),
                nonce_max: rand::random(),
                value: rand::random(),
            }
            .into(),
        };

        let mut buf = Vec::new();
        original.encode_to_seal(&mut buf).unwrap();

        let mut decode_buf = VecDeque::from(buf);
        let decoded = WorkClaim::decode_from_seal(&mut decode_buf).unwrap();

        assert_eq!(
            original.claim.as_value().unwrap(),
            decoded.claim.as_value().unwrap()
        );
        assert_eq!(
            original.work.as_value().unwrap().nonce_min,
            decoded.work.as_value().unwrap().nonce_min
        );
        assert_eq!(
            original.work.as_value().unwrap().nonce_max,
            decoded.work.as_value().unwrap().nonce_max
        );
        assert_eq!(
            original.work.as_value().unwrap().value,
            decoded.work.as_value().unwrap().value
        );
        assert!(decode_buf.is_empty());
    }
}
