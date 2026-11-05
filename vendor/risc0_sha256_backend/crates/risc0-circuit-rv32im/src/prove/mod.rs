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

mod hal;
#[cfg(test)]
mod tests;
mod witgen;

use anyhow::Result;
use cfg_if::cfg_if;
use risc0_core::scope;
use risc0_zkp::{core::hash::HashSuite, field::baby_bear::BabyBear};

use crate::execute::segment::Segment;

pub use witgen::PreflightResults;

const GLOBAL_MIX: usize = 0;
const GLOBAL_OUT: usize = 1;

pub type Seal = Vec<u32>;

pub trait SegmentProver {

    // Proves the operation result.
    fn prove(&self, segment: &Segment) -> Result<Seal> {
        scope!("prove");
        let results = self.preflight(segment)?;
        self.prove_core(results)
    }

    // Implements preflight.
    fn preflight(&self, segment: &Segment) -> Result<PreflightResults>;

    // Proves core.
    fn prove_core(&self, preflight_results: PreflightResults) -> Result<Seal>;
}

// Implements segment prover.
pub fn segment_prover() -> Result<Box<dyn SegmentProver>> {
    let hash_suite = risc0_zkp::core::hash::poseidon2::Poseidon2HashSuite::new_suite();
    segment_prover_with_hash_suite(hash_suite)
}

// Implements segment prover with hash suite.
pub fn segment_prover_with_hash_suite(
    hash_suite: HashSuite<BabyBear>,
) -> Result<Box<dyn SegmentProver>> {
    cfg_if! {
        if #[cfg(feature = "cuda")] {
            self::hal::cuda::segment_prover_with_hash_suite(hash_suite)

        } else {
            self::hal::cpu::segment_prover_with_hash_suite(hash_suite)
        }
    }
}
