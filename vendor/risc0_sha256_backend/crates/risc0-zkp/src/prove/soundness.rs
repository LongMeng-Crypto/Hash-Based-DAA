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

//! A soundness calculator for the RISC Zero STARK protocol that secures the
//! RISC Zero zkVM. Soundness for STARK protocols can be analyzed under a
//! number of different cryptographic assumptions.
//!
//! 1. Conjectured soundness using the Toy Problem Conjecture from ethSTARK
//! 2. Conjectured soundness using Conjecture 8.4 from [Proximity Gaps] and
//!    Conjecture 2.3 from [DEEP-FRI]
//! 3. Proven soundness in the list-decoding regime
//! 4. Proven soundness in the unique-decoding regime
//!
//! RISC Zero's on-chain verifier contracts target 97 bits of conjectured soundness,
//! using the Toy Problem Conjecture.
//!
//! This target assumes a SEGMENT_SIZE of 2^20 cycles.
//! Increasing SEGMENT_SIZE to the maximum of 2^24 cycles reduces the result to 95 bits of conjectured soundness.
//!
//! Use the following command to run the calculator:
//! RUST_LOG=risc0_zkp=info cargo run --release
//!
//! Running the calculator results in a terminal printout for scenarios (1) and (3) in the list above.
//! The calculator also includes code for scenarios (2) and (4).

use risc0_core::field::{baby_bear, ExtElem};

use crate::{
    adapter::{REGISTER_GROUP_ACCUM, REGISTER_GROUP_CODE, REGISTER_GROUP_DATA},
    hal::Hal,
    taps::TapSet,
    FRI_FOLD, FRI_MIN_DEGREE, INV_RATE,
};

const M: f32 = 16.0;

const RHO: f32 = 1.0 / INV_RATE as f32;

const ETA: f32 = 0.05;

// Implements proven.
pub fn proven<H: Hal>(taps: &TapSet, coeffs_size: usize) -> f32 {
    let params = parameters::<H>(taps, coeffs_size);
    let e_proximity_gap = params.e_proximity_gap_proven();

    let alpha = (1.0 + 1.0 / (2.0 * M)) * RHO.sqrt();

    let theta = 1.0 - alpha;
    let l_plus = {
        let rho_plus = (params.trace_domain_size + params.biggest_combo) / params.lde_domain_size;
        let m_plus = 1.0 / (params.biggest_combo * (alpha / rho_plus.sqrt() - 1.0));
        let m_plus = m_plus.ceil();

        (m_plus + 0.5) / rho_plus.sqrt()
    };
    soundness_error(&params, theta, e_proximity_gap, l_plus)
}

// Implements conjectured strict.
pub fn conjectured_strict<H: Hal>(taps: &TapSet, coeffs_size: usize) -> f32 {
    let params = parameters::<H>(taps, coeffs_size);
    let theta = 1.0 - RHO - ETA;
    let e_proximity_gap = params.e_proximity_gap_conjectured();
    let l_plus = {
        let rho_plus = (params.trace_domain_size + params.biggest_combo) / params.lde_domain_size;
        let epsilon_plus = 1.0 - rho_plus - theta;
        let c_rho = 1;
        (params.lde_domain_size / epsilon_plus).powi(c_rho)
    };
    soundness_error(&params, theta, e_proximity_gap, l_plus)
}

// Implements toy model security.
pub fn toy_model_security<H: Hal>(taps: &TapSet, coeffs_size: usize) -> f32 {
    let params = parameters::<H>(taps, coeffs_size);
    let ext_size = H::ExtElem::EXT_SIZE as f32;
    let field_size = baby_bear::P as f32;
    let ext_field_size = field_size.powf(ext_size);

    let plonk_plookup_error = params.plonk_plookup_error();
    let constraints_error = 1f32 / ext_field_size;
    let fri_error = RHO.powi(crate::QUERIES as i32);

    let sum = plonk_plookup_error + constraints_error + fri_error;
    sum.log2().abs()
}

// Implements soundness error.
fn soundness_error(params: &Params, theta: f32, e_proximity_gap: f32, l_plus: f32) -> f32 {
    let plonk_plookup_error = params.plonk_plookup_error();
    let fri_error = params.e_fri(theta, e_proximity_gap);
    let deep_ali_error = params.e_deep_ali(l_plus);
    let sum = plonk_plookup_error + fri_error + deep_ali_error;
    sum.log2().abs()
}

// Implements e fri queries.
fn e_fri_queries(theta: f32) -> f32 {
    (1.0 - theta).powi(crate::QUERIES as i32)
}

// Implements num folding rounds.
fn num_folding_rounds(coeffs_size: usize, ext_size: usize) -> usize {
    let mut num_folding_rounds = 0;
    let mut coeffs_size = coeffs_size;
    while coeffs_size / ext_size > FRI_MIN_DEGREE {
        coeffs_size /= FRI_FOLD;
        num_folding_rounds += 1;
    }
    num_folding_rounds
}

#[derive(Copy, Clone)]
struct Params {

    w_accum: f32,

    n_trace_polys: f32,

    max_degree: f32,

    num_segment_polynomials: f32,

    biggest_combo: f32,

    ext_size: usize,

    ext_field_size: f32,

    trace_domain_size: f32,

    lde_domain_size: f32,

    num_folding_rounds: usize,
}

// Implements parameters.
fn parameters<H: Hal>(taps: &TapSet, coeffs_size: usize) -> Params {

    let w_accum = taps.group_size(REGISTER_GROUP_ACCUM) as f32;

    let n_trace_polys = {
        let w_code = taps.group_size(REGISTER_GROUP_CODE) as f32;
        let w_data = taps.group_size(REGISTER_GROUP_DATA) as f32;

        w_accum + w_code + w_data
    };

    let max_degree = 5.0;

    let num_segment_polynomials = max_degree - 1.0;

    let biggest_combo = taps.combos().map(|combo| combo.size()).max().unwrap() as f32;

    let ext_size = H::ExtElem::EXT_SIZE;
    let field_size = baby_bear::P as f32;
    let ext_field_size = field_size.powf(ext_size as f32);
    let trace_domain_size = (coeffs_size / ext_size) as f32;
    let lde_domain_size = trace_domain_size * INV_RATE as f32;

    let num_folding_rounds = num_folding_rounds(coeffs_size, ext_size);

    Params {
        w_accum,
        n_trace_polys,
        max_degree,
        num_segment_polynomials,
        biggest_combo,
        ext_size,
        ext_field_size,
        trace_domain_size,
        lde_domain_size,
        num_folding_rounds,
    }
}

impl Params {

    // Implements plonk plookup error.
    fn plonk_plookup_error(&self) -> f32 {
        self.w_accum / self.ext_size as f32 * (self.max_degree - 2.0) * self.trace_domain_size
            / self.ext_field_size
    }

    // Implements e proximity gap proven.
    fn e_proximity_gap_proven(&self) -> f32 {
        (M + 0.5).powi(7) / (3.0 * RHO.sqrt().powi(3))
            * (self.lde_domain_size.powi(2) / self.ext_field_size)
    }

    // Implements e proximity gap conjectured.
    fn e_proximity_gap_conjectured(&self) -> f32 {
        let c_1 = 1;
        let c_2 = 1;

        let first_term = 1.0 / (ETA * RHO).powi(c_1);

        let second_term =
            (self.n_trace_polys * self.lde_domain_size).powi(c_2) / self.ext_field_size;

        first_term * second_term
    }

    // Implements e fri constant.
    fn e_fri_constant(&self, e_proximity_gap: f32) -> f32 {

        let first_term =
            (self.n_trace_polys + self.num_segment_polynomials - 0.5) * e_proximity_gap;

        let second_term = {
            let numerator = (2.0 * M + 1.0)
                * (self.lde_domain_size + 1.0)
                * (FRI_FOLD * self.num_folding_rounds) as f32;
            let denominator = RHO.sqrt() * self.ext_field_size;
            numerator / denominator
        };

        first_term + second_term
    }

    // Implements e fri.
    fn e_fri(&self, theta: f32, e_proximity_gap: f32) -> f32 {
        let e_fri_constant = self.e_fri_constant(e_proximity_gap);

        let e_fri_queries = e_fri_queries(theta);

        e_fri_constant + e_fri_queries
    }

    // Implements e ali.
    fn e_ali(&self, l_plus: f32) -> f32 {
        l_plus * self.n_trace_polys / self.ext_field_size
    }

    // Implements e deep.
    fn e_deep(&self, l_plus: f32) -> f32 {
        let h_plus = self.trace_domain_size + self.biggest_combo;

        let numerator =
            self.num_segment_polynomials * (h_plus - 1.0) + (self.trace_domain_size - 1.0);
        let denominator = self.ext_field_size - self.trace_domain_size - self.lde_domain_size;
        l_plus * numerator / denominator
    }

    // Implements e deep ali.
    fn e_deep_ali(&self, l_plus: f32) -> f32 {
        self.e_deep(l_plus) + self.e_ali(l_plus)
    }
}
