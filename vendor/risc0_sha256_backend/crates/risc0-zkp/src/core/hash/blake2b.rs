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

//! A Blake2b HashSuite.
use alloc::{boxed::Box, rc::Rc, vec::Vec};
use core::marker::PhantomData;

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use rand_core::{impls, RngCore};
use risc0_core::field::{
    baby_bear::{BabyBear, BabyBearElem, BabyBearExtElem},
    Elem, ExtElem,
};

use super::{HashFn, HashSuite, Rng, RngFactory};
use crate::core::digest::Digest;

pub trait Blake2b: Send + Sync {

    // Implements blake2b.
    fn blake2b<T: AsRef<[u8]>>(data: T) -> [u8; 32];
}

pub struct Blake2bCpuImpl;

pub type Blake2bCpuHashSuite = Blake2bHashSuite<Blake2bCpuImpl>;

impl Blake2b for Blake2bCpuImpl {

    // Implements blake2b.
    fn blake2b<T: AsRef<[u8]>>(data: T) -> [u8; 32] {
        let mut result = [0; 32];
        let mut hasher = Blake2bVar::new(32).expect("Initializing Blake2bVar failed");

        hasher.update(data.as_ref());
        hasher
            .finalize_variable(&mut result)
            .expect("Finalizing Blake2bVar failed");
        result
    }
}

struct Blake2bRngFactory<T: Blake2b> {
    phantom: PhantomData<T>,
}

impl<T: Blake2b> Blake2bRngFactory<T> {

    // Creates the operation result.
    fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

impl<T: Blake2b + 'static> RngFactory<BabyBear> for Blake2bRngFactory<T> {

    // Creates rng.
    fn new_rng(&self) -> Box<dyn Rng<BabyBear>> {
        let rng: Blake2bRng<T> = Blake2bRng::new();
        Box::new(rng)
    }
}

pub struct Blake2bHashSuite<T: Blake2b> {
    phantom: PhantomData<T>,
}

impl<T: Blake2b + 'static> Blake2bHashSuite<T> {

    // Creates suite.
    pub fn new_suite() -> HashSuite<BabyBear> {
        HashSuite {
            name: "blake2b".into(),
            hashfn: Rc::new(Blake2bHashFn::<T>::new()),
            rng: Rc::new(Blake2bRngFactory::<T>::new()),
        }
    }
}

struct Blake2bHashFn<T: Blake2b> {
    phantom: PhantomData<T>,
}

impl<T: Blake2b> Blake2bHashFn<T> {

    // Creates the operation result.
    fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

impl<T: Blake2b> HashFn<BabyBear> for Blake2bHashFn<T> {

    // Hashes pair.
    fn hash_pair(&self, a: &Digest, b: &Digest) -> Box<Digest> {
        let concat = [a.as_bytes(), b.as_bytes()].concat();
        Box::new(Digest::from(T::blake2b(concat)))
    }

    // Hashes elem slice.
    fn hash_elem_slice(&self, slice: &[BabyBearElem]) -> Box<Digest> {
        let mut data = Vec::<u8>::new();
        for el in slice {
            data.extend_from_slice(el.as_u32_montgomery().to_be_bytes().as_slice());
        }
        Box::new(Digest::from(T::blake2b(data)))
    }

    // Hashes ext elem slice.
    fn hash_ext_elem_slice(&self, slice: &[BabyBearExtElem]) -> Box<Digest> {
        let mut data = Vec::<u8>::new();
        for ext_el in slice {
            for el in ext_el.subelems() {
                data.extend_from_slice(el.as_u32_montgomery().to_be_bytes().as_slice());
            }
        }
        Box::new(Digest::from(T::blake2b(data)))
    }
}

pub struct Blake2bRng<T: Blake2b> {
    current: [u8; 32],
    hasher: PhantomData<T>,
}

impl<T: Blake2b> Blake2bRng<T> {

    // Creates the operation result.
    fn new() -> Self {
        Self {
            current: [0; 32],
            hasher: Default::default(),
        }
    }
}

impl<T: Blake2b> Rng<BabyBear> for Blake2bRng<T> {

    // Implements mix.
    fn mix(&mut self, val: &Digest) {
        let concat = [self.current.as_ref(), val.as_bytes()].concat();
        self.current = T::blake2b(concat);
    }

    // Implements random bits.
    fn random_bits(&mut self, bits: usize) -> u32 {
        ((1 << bits) - 1) & self.next_u32()
    }

    // Implements random elem.
    fn random_elem(&mut self) -> BabyBearElem {
        BabyBearElem::random(self)
    }

    // Implements random ext elem.
    fn random_ext_elem(&mut self) -> BabyBearExtElem {
        BabyBearExtElem::random(self)
    }
}

impl<T: Blake2b> RngCore for Blake2bRng<T> {

    // Implements next u32.
    fn next_u32(&mut self) -> u32 {
        let next = T::blake2b(self.current);
        self.current = next;
        ((next[0] as u32) << 24)
            + ((next[1] as u32) << 16)
            + ((next[2] as u32) << 8)
            + (next[3] as u32)
    }

    // Implements next u64.
    fn next_u64(&mut self) -> u64 {
        impls::next_u64_via_u32(self)
    }

    // Implements fill bytes.
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        impls::fill_bytes_via_next(self, dest);
    }
}
