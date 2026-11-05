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

use risc0_core::field::{Elem, Field};

use crate::core::{
    digest::Digest,
    hash::{Rng, RngFactory},
};

pub struct WriteIOP<F: Field> {
    pub proof: Vec<u32>,
    pub rng: Box<dyn Rng<F>>,
}

impl<F: Field> WriteIOP<F> {

    // Creates the operation result.
    pub fn new(rng: &dyn RngFactory<F>) -> Self {
        Self {
            proof: Vec::new(),
            rng: rng.new_rng(),
        }
    }

    // Writes u32 slice.
    pub fn write_u32_slice(&mut self, slice: &[u32]) {
        self.proof.extend_from_slice(slice);
    }

    // Writes field elem slice.
    pub fn write_field_elem_slice<T: Elem>(&mut self, slice: &[T]) {
        self.proof.extend(Elem::as_u32_slice(slice))
    }

    // Writes pod slice.
    pub fn write_pod_slice<T: bytemuck::Pod>(&mut self, slice: &[T]) {
        self.proof.extend(bytemuck::cast_slice(slice))
    }

    // Implements commit.
    pub fn commit(&mut self, message: &Digest) {
        self.rng.mix(message);
    }

    // Implements random bits.
    pub fn random_bits(&mut self, bits: usize) -> u32 {
        self.rng.random_bits(bits)
    }

    // Implements random elem.
    pub fn random_elem(&mut self) -> F::Elem {
        self.rng.random_elem()
    }

    // Implements random ext elem.
    pub fn random_ext_elem(&mut self) -> F::ExtElem {
        self.rng.random_ext_elem()
    }
}
