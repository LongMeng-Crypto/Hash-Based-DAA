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

use std::sync::Arc;

use anyhow::Result;

use risc0_zkp::{
    core::{digest::Digest, hash::HashSuite},
    field::baby_bear::{BabyBear, BabyBearElem},
    hal::{self, Hal},
    prove::poly_group::PolyGroup,
    ZK_CYCLES,
};

use super::RECURSION_CODE_SIZE;

#[derive(Clone)]
pub struct Program {

    pub code: Arc<[BabyBearElem]>,

    pub code_size: usize,

    pub po2: usize,
}

impl Program {

    // Implements from encoded.
    pub fn from_encoded(encoded: &[u32], po2: usize) -> Self {
        let prog = Self {
            code: encoded
                .iter()
                .copied()
                .map(BabyBearElem::from)
                .collect::<Vec<_>>()
                .into(),
            code_size: RECURSION_CODE_SIZE,
            po2,
        };
        assert_eq!(prog.code.len() % RECURSION_CODE_SIZE, 0);
        assert!(prog.code.len() <= (RECURSION_CODE_SIZE * ((1 << po2) - ZK_CYCLES)));
        prog
    }

    // Implements code rows.
    pub fn code_rows(&self) -> usize {
        self.code.len() / self.code_size
    }

    // Implements code by row.
    pub fn code_by_row(&self) -> impl Iterator<Item = &[BabyBearElem]> {
        self.code.as_ref().chunks(self.code_size)
    }

    // Computes control id.
    pub fn compute_control_id(&self, hash_suite: HashSuite<BabyBear>) -> Result<Digest> {
        #[cfg(feature = "cuda")]
        let digest =
            self.compute_control_id_inner(&hal::cuda::CudaHal::new_from_hash_suite(hash_suite)?);

        #[cfg(not(feature = "cuda"))]
        let digest = self.compute_control_id_inner(&hal::cpu::CpuHal::new(hash_suite));

        Ok(digest)
    }

    // Computes control id inner.
    fn compute_control_id_inner(&self, hal: &impl Hal<Elem = BabyBearElem>) -> Digest {
        let cycles = 1 << self.po2;

        let mut code = vec![BabyBearElem::default(); cycles * self.code_size];

        for (cycle, row) in self.code_by_row().enumerate() {
            for (i, elem) in row.iter().enumerate() {
                code[cycles * i + cycle] = *elem;
            }
        }
        let coeffs = hal.copy_from_elem("coeffs", &code);

        hal.batch_interpolate_ntt(&coeffs, self.code_size);
        hal.zk_shift(&coeffs, self.code_size);

        let code_group = PolyGroup::new(hal, coeffs, self.code_size, cycles, "code");
        let root = *code_group.merkle.root();
        tracing::trace!("Computed recursion code: {root:?}");
        root
    }
}
