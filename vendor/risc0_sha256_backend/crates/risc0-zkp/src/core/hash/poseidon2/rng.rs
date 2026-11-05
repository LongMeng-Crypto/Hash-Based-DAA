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

//! A Poseidon2 based CRNG used in Fiat-Shamir.

use risc0_core::field::{
    baby_bear::{BabyBear, BabyBearExtElem, Elem},
    ExtElem,
};

use super::{consts::CELLS, poseidon2_mix, CELLS_OUT, CELLS_RATE};
use crate::core::{digest::Digest, hash::Rng};

#[derive(Clone, Debug)]
pub struct Poseidon2Rng {

    cells: [Elem; CELLS],

    pool_used: usize,
}

impl Default for Poseidon2Rng {

    // Implements default.
    fn default() -> Self {
        Self::new()
    }
}

impl Poseidon2Rng {

    // Creates the operation result.
    pub fn new() -> Self {
        Self {
            cells: [Elem::new(0); CELLS],
            pool_used: 0,
        }
    }
}

impl Rng<BabyBear> for Poseidon2Rng {

    // Implements mix.
    fn mix(&mut self, val: &Digest) {

        if self.pool_used != 0 {
            poseidon2_mix(&mut self.cells);
            self.pool_used = 0;
        }

        for i in 0..CELLS_OUT {
            self.cells[i] += Elem::new_raw(val.as_words()[i]);
        }

        poseidon2_mix(&mut self.cells);
    }

    // Implements random bits.
    fn random_bits(&mut self, bits: usize) -> u32 {
        let mut val = self.random_elem().as_u32();
        for _ in 0..3 {
            let new_val = self.random_elem().as_u32();
            if val == 0 {
                val = new_val;
            }
        }
        ((1 << bits) - 1) & val
    }

    // Implements random elem.
    fn random_elem(&mut self) -> Elem {
        if self.pool_used == CELLS_RATE {
            poseidon2_mix(&mut self.cells);
            self.pool_used = 0;
        }
        let out = self.cells[self.pool_used];
        self.pool_used += 1;
        out
    }

    // Implements random ext elem.
    fn random_ext_elem(&mut self) -> BabyBearExtElem {
        ExtElem::from_subelems((0..4).map(|_| self.random_elem()))
    }
}
