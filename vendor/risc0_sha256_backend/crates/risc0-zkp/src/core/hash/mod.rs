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

//! Traits to configure which cryptographic primitives the ZKP uses

pub mod blake2b;
pub mod poseidon2;
#[cfg(feature = "prove")]
pub mod poseidon_254;
pub mod sha;

use alloc::{boxed::Box, rc::Rc, string::String};

use risc0_core::field::{baby_bear::BabyBear, Field};

use super::digest::Digest;

pub trait HashFn<F: Field>: Send + Sync {

    // Hashes pair.
    fn hash_pair(&self, a: &Digest, b: &Digest) -> Box<Digest>;

    // Hashes elem slice.
    fn hash_elem_slice(&self, slice: &[F::Elem]) -> Box<Digest>;

    // Hashes ext elem slice.
    fn hash_ext_elem_slice(&self, slice: &[F::ExtElem]) -> Box<Digest>;

    // Checks digest valid.
    fn is_digest_valid(&self, digest: &Digest) -> bool {
        #![expect(unused_variables)]
        true
    }
}

pub trait Rng<F: Field> {

    // Implements mix.
    fn mix(&mut self, val: &Digest);

    // Implements random bits.
    fn random_bits(&mut self, bits: usize) -> u32;

    // Implements random elem.
    fn random_elem(&mut self) -> F::Elem;

    // Implements random ext elem.
    fn random_ext_elem(&mut self) -> F::ExtElem;
}

pub trait RngFactory<F: Field> {

    // Creates rng.
    fn new_rng(&self) -> Box<dyn Rng<F>>;
}

pub struct HashSuite<F: Field> {

    pub name: String,

    pub hashfn: Rc<dyn HashFn<F>>,

    pub rng: Rc<dyn RngFactory<F>>,
}

impl<F: Field> Clone for HashSuite<F> {

    // Implements clone.
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            hashfn: self.hashfn.clone(),
            rng: self.rng.clone(),
        }
    }
}

// Hashes suite from name.
pub fn hash_suite_from_name(name: impl AsRef<str>) -> Option<HashSuite<BabyBear>> {
    match name.as_ref() {
        "sha-256" => Some(sha::Sha256HashSuite::new_suite()),
        "poseidon2" => Some(poseidon2::Poseidon2HashSuite::new_suite()),
        "blake2b" => Some(blake2b::Blake2bCpuHashSuite::new_suite()),
        #[cfg(feature = "prove")]
        "poseidon_254" => Some(poseidon_254::Poseidon254HashSuite::new_suite()),
        _ => None,
    }
}
