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

use risc0_core::scope_with;

use crate::{
    core::log2_ceil,
    hal::{Buffer, Hal},
    prove::merkle::MerkleTreeProver,
    INV_RATE, QUERIES,
};

pub struct PolyGroup<H: Hal> {
    pub coeffs: H::Buffer<H::Elem>,
    pub count: usize,
    pub evaluated: H::Buffer<H::Elem>,
    pub merkle: MerkleTreeProver<H>,
}

impl<H: Hal> PolyGroup<H> {

    // Creates the operation result.
    pub fn new(
        hal: &H,
        coeffs: H::Buffer<H::Elem>,
        count: usize,
        size: usize,
        name: &'static str,
    ) -> Self {
        scope_with!("poly_group({})", name);
        assert_eq!(coeffs.size(), count * size);
        let domain = size * INV_RATE;
        let evaluated = hal.alloc_elem("evaluated", count * domain);
        hal.batch_expand_into_evaluate_ntt(&evaluated, &coeffs, count, log2_ceil(INV_RATE));
        hal.batch_bit_reverse(&coeffs, count);
        let merkle = MerkleTreeProver::new(hal, &evaluated, domain, count, QUERIES);
        PolyGroup {
            coeffs,
            count,
            evaluated,
            merkle,
        }
    }
}
