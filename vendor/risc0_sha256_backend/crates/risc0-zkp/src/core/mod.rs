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

//! Core module used to implement a zk-STARK prover and verifier.

#![allow(missing_docs)]

extern crate alloc;

pub mod digest;
pub mod hash;
pub mod ntt;
pub mod poly;

use rand_core::RngCore;

// Implements to po2.
pub fn to_po2(x: usize) -> usize {
    (31 - (x as u32).leading_zeros()) as usize
}

#[inline]

// Implements log2 ceil.
pub const fn log2_ceil(value: usize) -> usize {
    let mut result = 0;
    while (1 << result) < value {
        result += 1;
    }
    result
}

pub trait Random {

    // Implements random.
    fn random<R: RngCore>(rng: &mut R) -> Self;
}

impl Random for u32 {

    // Implements random.
    fn random<R: RngCore>(rng: &mut R) -> Self {
        rng.next_u32()
    }
}
