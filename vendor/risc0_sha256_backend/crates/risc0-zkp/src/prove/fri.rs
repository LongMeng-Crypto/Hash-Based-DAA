// Copyright 2024 RISC Zero, Inc.
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

use risc0_core::{field::ExtElem, scope};
use tracing::debug;

use crate::{
    core::log2_ceil,
    hal::{Buffer, Hal},
    prove::{merkle::MerkleTreeProver, write_iop::WriteIOP},
    FRI_FOLD, FRI_MIN_DEGREE, INV_RATE, QUERIES,
};

struct ProveRoundInfo<H: Hal> {
    domain: usize,
    coeffs: H::Buffer<H::Elem>,
    merkle: MerkleTreeProver<H>,
}

impl<H: Hal> ProveRoundInfo<H> {

    // Creates the operation result.
    pub fn new(hal: &H, iop: &mut WriteIOP<H::Field>, coeffs: &H::Buffer<H::Elem>) -> Self {
        debug!("Doing FRI folding");
        let ext_size = H::ExtElem::EXT_SIZE;

        let size = coeffs.size() / ext_size;

        let domain = size * INV_RATE;

        let evaluated = hal.alloc_elem("evaluated", domain * ext_size);

        hal.batch_expand_into_evaluate_ntt(&evaluated, coeffs, ext_size, log2_ceil(INV_RATE));

        let merkle = MerkleTreeProver::new(
            hal,
            &evaluated,
            domain / FRI_FOLD,
            FRI_FOLD * ext_size,
            QUERIES,
        );

        merkle.commit(iop);

        let fold_mix = iop.random_ext_elem();

        let out_coeffs = hal.alloc_elem("out_coeffs", size / FRI_FOLD * ext_size);

        hal.fri_fold(&out_coeffs, coeffs, &fold_mix);
        ProveRoundInfo {
            domain,
            coeffs: out_coeffs,
            merkle,
        }
    }

    // Proves query.
    pub fn prove_query(&mut self, hal: &H, iop: &mut WriteIOP<H::Field>, pos: &mut usize) {

        let group = *pos % (self.domain / FRI_FOLD);

        self.merkle.prove(hal, iop, group);

        *pos = group;
    }
}

// Implements fri prove.
pub fn fri_prove<H: Hal, F>(
    hal: &H,
    iop: &mut WriteIOP<H::Field>,
    coeffs: &H::Buffer<H::Elem>,
    inner: F,
) where
    F: Fn(&mut WriteIOP<H::Field>, usize),
{
    scope!("fri_prove");
    let ext_size = H::ExtElem::EXT_SIZE;
    let orig_domain = coeffs.size() / ext_size * INV_RATE;
    let mut rounds = Vec::new();
    let mut coeffs = coeffs.clone();
    while coeffs.size() / ext_size > FRI_MIN_DEGREE {
        let round = ProveRoundInfo::new(hal, iop, &coeffs);
        coeffs = round.coeffs.clone();
        rounds.push(round);
    }

    let final_coeffs = hal.alloc_elem("final_coeffs", coeffs.size());
    hal.eltwise_copy_elem(&final_coeffs, &coeffs);
    hal.batch_bit_reverse(&final_coeffs, ext_size);

    final_coeffs.view(|view| {
        iop.write_field_elem_slice::<H::Elem>(view);
        let digest = hal.get_hash_suite().hashfn.hash_elem_slice(view);
        iop.commit(&digest);
    });

    debug!("Doing Queries");
    for _ in 0..QUERIES {

        let mut pos = iop.random_bits(log2_ceil(orig_domain)) as usize;

        inner(iop, pos);

        for round in rounds.iter_mut() {
            round.prove_query(hal, iop, &mut pos);
        }
    }
}
