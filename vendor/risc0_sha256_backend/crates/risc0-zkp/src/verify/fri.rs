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

use alloc::vec::Vec;
use core::ops::DerefMut;

use risc0_core::field::{Elem, ExtElem, Field, RootsOfUnity};

use super::Verifier;
use crate::{
    core::{
        hash::HashFn,
        log2_ceil,
        ntt::{bit_reverse, interpolate_ntt},
    },
    verify::{merkle::MerkleTreeVerifier, read_iop::ReadIOP, VerificationError},
    FRI_FOLD, FRI_FOLD_PO2, FRI_MIN_DEGREE, INV_RATE, QUERIES,
};

struct VerifyRoundInfo<'a, F: Field> {
    domain: usize,
    merkle: MerkleTreeVerifier<'a>,
    mix: F::ExtElem,
}

impl<'a, F: Field> VerifyRoundInfo<'a, F> {

    // Creates the operation result.
    pub fn new(
        iop: &mut ReadIOP<'a, F>,
        hashfn: &dyn HashFn<F>,
        in_domain: usize,
    ) -> Result<Self, VerificationError> {
        let domain = in_domain / FRI_FOLD;
        Ok(VerifyRoundInfo {
            domain,
            merkle: MerkleTreeVerifier::new(
                iop,
                hashfn,
                domain,
                FRI_FOLD * F::ExtElem::EXT_SIZE,
                QUERIES,
            )?,
            mix: iop.random_ext_elem(),
        })
    }
}

impl<'a, F> Verifier<'a, F>
where
    F: Field,
{

    // Verifies query.
    fn verify_query(
        &self,
        round: &mut VerifyRoundInfo<'a, F>,
        pos: &mut usize,
        goal: &mut F::ExtElem,
    ) -> Result<(), VerificationError> {
        let quot = *pos / round.domain;
        let group = *pos % round.domain;

        let hashfn = self.suite.hashfn.as_ref();
        let data = round.merkle.verify(self.iop().deref_mut(), hashfn, group)?;
        let mut data_ext: Vec<F::ExtElem> = (0..FRI_FOLD)
            .map(|i| {
                let mut inps = Vec::with_capacity(F::ExtElem::EXT_SIZE);
                for j in 0..F::ExtElem::EXT_SIZE {
                    inps.push(data[j * FRI_FOLD + i]);
                }
                F::ExtElem::from_subelems(inps)
            })
            .collect();

        if data_ext[quot] != *goal {
            return Err(VerificationError::InvalidProof);
        }

        let root_po2 = log2_ceil(FRI_FOLD * round.domain);
        let inv_wk = F::Elem::ROU_REV[root_po2].pow(group);

        interpolate_ntt::<F::Elem, F::ExtElem>(&mut data_ext);
        bit_reverse(&mut data_ext);
        *goal = self.poly_eval(&data_ext, round.mix * inv_wk);

        *pos = group;
        Ok(())
    }

    // Implements fri verify.
    pub fn fri_verify<InnerFn>(&self, mut inner: InnerFn) -> Result<(), VerificationError>
    where
        InnerFn: FnMut(usize) -> Result<F::ExtElem, VerificationError>,
    {
        let mut degree: usize = self.tot_cycles;
        let hashfn = self.suite.hashfn.as_ref();
        let orig_domain = INV_RATE * degree;
        let mut domain = orig_domain;

        let rounds_capacity = log2_ceil(degree.div_ceil(FRI_FOLD).div_ceil(FRI_FOLD_PO2));
        let mut rounds = Vec::with_capacity(rounds_capacity);
        while degree > FRI_MIN_DEGREE {
            rounds.push(VerifyRoundInfo::new(
                self.iop().deref_mut(),
                hashfn,
                domain,
            )?);
            domain /= FRI_FOLD;
            degree /= FRI_FOLD;
        }

        assert!(
            rounds.len() <= rounds_capacity,
            "Did not allocate enough rounds; needed {} for degree {} but only allocated {}",
            rounds.len(),
            degree,
            rounds_capacity
        );

        let final_coeffs = self
            .iop()
            .read_field_elem_slice(F::ExtElem::EXT_SIZE * degree)?;
        let final_digest = hashfn.hash_elem_slice(final_coeffs);
        self.iop().commit(&final_digest);

        let gen = <F::Elem as RootsOfUnity>::ROU_FWD[log2_ceil(domain)];

        let mut poly_buf: Vec<F::ExtElem> = Vec::with_capacity(degree);
        for _ in 0..QUERIES {
            let mut pos = self.iop().random_bits(log2_ceil(orig_domain)) as usize;

            let mut goal = inner(pos)?;

            for round in &mut rounds {
                self.verify_query(round, &mut pos, &mut goal)?;
            }

            let x = gen.pow(pos);

            poly_buf.clear();
            poly_buf.extend((0..degree).map(|i| {
                F::ExtElem::from_subelems(
                    (0..F::ExtElem::EXT_SIZE).map(|j| final_coeffs[j * degree + i]),
                )
            }));
            let fx = self.poly_eval(poly_buf.as_slice(), F::ExtElem::from_subfield(&x));
            if fx != goal {
                return Err(VerificationError::InvalidProof);
            }
        }
        Ok(())
    }
}
