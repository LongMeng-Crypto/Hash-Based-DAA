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

//! Prover implementation for the recursion VM.
//!
//! This module contains the recursion [Prover].

mod hal;
mod preflight;
mod program;
mod witgen;
pub mod zkr;

use std::{collections::VecDeque, fmt::Debug, rc::Rc};

use anyhow::Result;
use cfg_if::cfg_if;
use risc0_core::scope;
use risc0_zkp::{
    adapter::{CircuitInfo, PROOF_SYSTEM_INFO},
    core::digest::Digest,
    field::{
        baby_bear::{BabyBear, BabyBearElem, BabyBearExtElem},
        Elem as _,
    },
    hal::{Buffer, CircuitHal, Hal},
};
use serde::{Deserialize, Serialize};

use self::{
    hal::{CircuitAccumulator, CircuitWitnessGenerator},
    preflight::Preflight,
    witgen::WitnessGenerator,
};
use crate::{
    taps::TAPSET, CircuitImpl, REGISTER_GROUP_ACCUM, REGISTER_GROUP_CTRL, REGISTER_GROUP_DATA,
};

pub use self::program::Program;

const RECURSION_CODE_SIZE: usize = 23;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RecursionReceipt {
    pub seal: Vec<u32>,
    pub output: Vec<u32>,
}

impl RecursionReceipt {

    // Implements seal size.
    pub fn seal_size(&self) -> usize {
        core::mem::size_of_val(self.seal.as_slice())
    }

    // Implements out stream.
    pub fn out_stream(&self) -> VecDeque<u32> {
        let mut vec: VecDeque<u32> = VecDeque::new();
        vec.extend(self.output.iter());
        vec
    }
}

pub trait RecursionProver {

    // Proves the operation result.
    fn prove(&self, program: &Program, input: RecursionInput) -> Result<RecursionReceipt>;
}

// Implements recursion prover.
pub fn recursion_prover(hashfn: &str) -> Result<Rc<dyn RecursionProver>> {
    cfg_if! {
        if #[cfg(feature = "cuda")] {
            self::hal::cuda::recursion_prover(hashfn)

        } else {
            self::hal::cpu::recursion_prover(hashfn)
        }
    }
}

pub struct Prover {
    program: Program,
    hashfn: String,
    input: RecursionInput,
}

#[derive(Default)]
pub struct RecursionInput {
    chunks: VecDeque<VecDeque<u32>>,
}

impl RecursionInput {

    // Implements push.
    fn push(&mut self, input: &[u32]) {
        if !input.is_empty() {
            self.chunks.push_back(input.iter().copied().collect());
        }
    }

    // Implements pop front.
    pub(crate) fn pop_front(&mut self) -> Option<u32> {
        loop {
            let chunk = self.chunks.front_mut()?;
            if let Some(word) = chunk.pop_front() {
                return Some(word);
            }
            self.chunks.pop_front();
        }
    }

    // Implements take.
    pub(crate) fn take(&mut self, count: usize) -> Vec<u32> {
        (0..count)
            .map(|_| self.pop_front().expect("recursion input underflow"))
            .collect()
    }
}

#[non_exhaustive]
pub enum DigestKind {
    Poseidon2,
    Sha256,
}

impl Prover {

    // Creates the operation result.
    pub fn new(program: Program, hashfn: &str) -> Self {
        Self {
            program,
            hashfn: hashfn.to_string(),
            input: RecursionInput::default(),
        }
    }

    // Adds input.
    pub fn add_input(&mut self, input: &[u32]) {
        self.input.push(input);
    }

    // Adds input digest.
    pub fn add_input_digest(&mut self, digest: &Digest, kind: DigestKind) {
        match kind {

            DigestKind::Poseidon2 => self.add_input(digest.as_words()),

            DigestKind::Sha256 => self.add_input(bytemuck::cast_slice(
                &digest
                    .as_words()
                    .iter()
                    .copied()
                    .flat_map(|x| [x & 0xffff, x >> 16])
                    .map(BabyBearElem::new)
                    .collect::<Vec<_>>(),
            )),
        }
    }

    // Runs the operation result.
    pub fn run(&mut self) -> Result<RecursionReceipt> {
        let prover = recursion_prover(&self.hashfn)?;
        prover.prove(&self.program, std::mem::take(&mut self.input))
    }
}

pub(crate) struct RecursionProverImpl<H, C>
where
    H: Hal<Field = BabyBear, Elem = BabyBearElem, ExtElem = BabyBearExtElem>,
    C: CircuitHal<H> + CircuitWitnessGenerator<H>,
{
    hal: Rc<H>,
    circuit_hal: Rc<C>,
}

impl<H, C> RecursionProver for RecursionProverImpl<H, C>
where
    H: Hal<Field = BabyBear, Elem = BabyBearElem, ExtElem = BabyBearExtElem>,
    C: CircuitHal<H> + CircuitWitnessGenerator<H> + CircuitAccumulator<H>,
{

    // Proves the operation result.
    fn prove(&self, program: &Program, input: RecursionInput) -> Result<RecursionReceipt> {
        scope!("prove");

        let preflight = self.preflight(program, input)?;

        let witgen = WitnessGenerator::new(
            self.hal.as_ref(),
            self.circuit_hal.as_ref(),
            program,
            &preflight,
        )?;

        let global = &witgen.global;

        let seal = scope!("prove", {
            let mut prover = risc0_zkp::prove::Prover::new(self.hal.as_ref(), TAPSET);
            let hashfn = &self.hal.get_hash_suite().hashfn;

            let mix = scope!("main", {

                prover
                    .iop()
                    .commit(&hashfn.hash_elem_slice(&PROOF_SYSTEM_INFO.encode()));
                prover
                    .iop()
                    .commit(&hashfn.hash_elem_slice(&CircuitImpl::CIRCUIT_INFO.encode()));

                let global_len = global.size();
                let mut header = vec![BabyBearElem::ZERO; global_len + 1];
                global.view_mut(|view| {
                    for (i, elem) in view.iter_mut().enumerate() {
                        *elem = elem.valid_or_zero();
                        header[i] = *elem;
                    }
                    header[global_len] = BabyBearElem::new_raw(program.po2 as u32);
                });

                let header_digest = hashfn.hash_elem_slice(&header);
                prover.iop().commit(&header_digest);
                prover.iop().write_field_elem_slice(header.as_slice());
                prover.set_po2(program.po2);

                prover.commit_group(REGISTER_GROUP_CTRL, &witgen.ctrl);
                prover.commit_group(REGISTER_GROUP_DATA, &witgen.data);

                let mix: [BabyBearElem; CircuitImpl::MIX_SIZE] =
                    std::array::from_fn(|_| prover.iop().random_elem());

                let mix = witgen.accum(&self.hal, self.circuit_hal.as_ref(), &mix)?;

                prover.commit_group(REGISTER_GROUP_ACCUM, &witgen.accum);

                mix
            });

            prover.finalize(&[&mix, global], self.circuit_hal.as_ref())
        });

        Ok(RecursionReceipt {
            seal,
            output: preflight.output,
        })
    }
}

impl<H, C> RecursionProverImpl<H, C>
where
    H: Hal<Field = BabyBear, Elem = BabyBearElem, ExtElem = BabyBearExtElem>,
    C: CircuitHal<H> + CircuitWitnessGenerator<H>,
{

    // Creates the operation result.
    pub fn new(hal: Rc<H>, circuit_hal: Rc<C>) -> Self {
        Self { hal, circuit_hal }
    }

    // Implements preflight.
    fn preflight(&self, program: &Program, input: RecursionInput) -> Result<Preflight> {
        scope!("preflight");

        let mut preflight = Preflight::new(input);
        for (cycle, row) in program.code_by_row().enumerate() {
            preflight.step(cycle, row)?
        }

        Ok(preflight)
    }
}
