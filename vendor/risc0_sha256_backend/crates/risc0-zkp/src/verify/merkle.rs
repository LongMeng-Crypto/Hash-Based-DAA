// Copyright 2026 RISC Zero, Inc.
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

use alloc::{boxed::Box, vec::Vec};

use risc0_core::field::Field;

use crate::{
    core::{digest::Digest, hash::HashFn},
    merkle::MerkleTreeParams,
    verify::{read_iop::ReadIOP, VerificationError},
};

pub(crate) struct MerkleTreeVerifier<'a> {
    params: MerkleTreeParams,

    top: &'a [Digest],

    #[allow(clippy::vec_box)]
    rest: Vec<Box<Digest>>,
}

trait SplitMerkleIndex {

    // Implements idx to top.
    fn idx_to_top(&self, idx: usize) -> usize;

    // Implements idx to rest.
    fn idx_to_rest(&self, idx: usize) -> usize;
}

impl SplitMerkleIndex for MerkleTreeParams {

    #[track_caller]

    // Implements idx to top.
    fn idx_to_top(&self, idx: usize) -> usize {
        debug_assert!(
            idx >= self.top_size,
            "idx = {idx}, top_size = {}",
            self.top_size
        );
        debug_assert!(
            idx < 2 * self.top_size,
            "idx = {idx}, top_size = {}",
            self.top_size
        );
        idx - self.top_size
    }

    #[track_caller]

    // Implements idx to rest.
    fn idx_to_rest(&self, idx: usize) -> usize {
        debug_assert!(
            idx < self.top_size,
            "idx = {idx}, top_size = {}",
            self.top_size
        );
        debug_assert!(idx >= 1, "idx = {idx}, top_size = {}", self.top_size);
        idx - 1
    }
}

impl<'a> MerkleTreeVerifier<'a> {

    // Creates the operation result.
    pub fn new<F: Field>(
        iop: &mut ReadIOP<'a, F>,
        hashfn: &dyn HashFn<F>,
        row_size: usize,
        col_size: usize,
        queries: usize,
    ) -> Result<Self, VerificationError> {
        let params = MerkleTreeParams::new(row_size, col_size, queries);

        let top = iop.read_pod_slice(params.top_size)?;

        let mut rest = Vec::with_capacity(params.top_size - 1);

        let fill_rest = rest.spare_capacity_mut();

        if !fill_rest.is_empty() {
            for i in (params.top_size / 2..params.top_size).rev() {
                let top_idx = params.idx_to_top(2 * i);
                let (left, right) = (&top[top_idx], &top[top_idx + 1]);
                if !hashfn.is_digest_valid(left) || !hashfn.is_digest_valid(right) {
                    tracing::debug!("top digests read from iop are invalid");
                    return Err(VerificationError::ReceiptFormatError);
                }
                fill_rest[params.idx_to_rest(i)].write(hashfn.hash_pair(left, right));
            }
        }
        for i in (1..params.top_size / 2).rev() {

            let upper_rest_idx = params.idx_to_rest(i * 2);
            fill_rest[params.idx_to_rest(i)].write(hashfn.hash_pair(
                unsafe { fill_rest[upper_rest_idx].assume_init_ref() },
                unsafe { fill_rest[upper_rest_idx + 1].assume_init_ref() },
            ));
        }

        unsafe {
            let filled = fill_rest.len();
            rest.set_len(filled);
        };

        let verifier = MerkleTreeVerifier { params, top, rest };
        iop.commit(verifier.root());
        Ok(verifier)
    }

    // Implements root.
    pub fn root(&self) -> &Digest {
        if self.rest.is_empty() {
            &self.top[self.params.idx_to_top(1)]
        } else {
            &self.rest[self.params.idx_to_rest(1)]
        }
    }

    // Verifies the operation result.
    pub fn verify<F: Field>(
        &self,
        iop: &mut ReadIOP<'a, F>,
        hashfn: &dyn HashFn<F>,
        mut idx: usize,
    ) -> Result<&'a [F::Elem], VerificationError> {
        if idx >= self.params.row_size {
            return Err(VerificationError::MerkleQueryOutOfRange {
                idx,
                rows: self.params.row_size,
            });
        }

        let out: &[F::Elem] = iop.read_field_elem_slice(self.params.col_size)?;

        let mut cur = hashfn.hash_elem_slice(out);

        idx += self.params.row_size;
        while idx >= 2 * self.params.top_size {

            let low_bit = idx % 2;

            let other: &Digest = match iop.read_pod_slice(1)? {
                [other] => other,
                _ => unreachable!(),
            };
            if !hashfn.is_digest_valid(other) {
                tracing::debug!("merkle proof node read from iop is invalid");
                return Err(VerificationError::ReceiptFormatError);
            }

            idx /= 2;
            if low_bit == 1 {
                cur = hashfn.hash_pair(other, &cur);
            } else {
                cur = hashfn.hash_pair(&cur, other);
            }
        }

        let present_hash: &Digest = if idx >= self.params.top_size {
            &self.top[self.params.idx_to_top(idx)]
        } else {
            &self.rest[self.params.idx_to_rest(idx)]
        };
        if *present_hash == *cur {
            Ok(out)
        } else {
            Err(VerificationError::InvalidProof)
        }
    }
}
