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

#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(rustdoc::broken_intra_doc_links)]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;

pub mod adapter;
pub mod core;
#[cfg(feature = "prove")]
pub mod hal;
pub mod layout;
mod merkle;
#[cfg(feature = "prove")]
pub mod prove;
pub mod taps;
pub mod verify;

pub use risc0_core::field;

pub const MIN_CYCLES_PO2: usize = 13;
pub const MIN_CYCLES: usize = 1 << MIN_CYCLES_PO2;
pub const MAX_CYCLES_PO2: usize = 24;
pub const MAX_CYCLES: usize = 1 << MAX_CYCLES_PO2;

pub const QUERIES: usize = 50;
pub const ZK_CYCLES: usize = 1024;
pub const MIN_PO2: usize = core::log2_ceil(1 + ZK_CYCLES);

pub const INV_RATE: usize = 4;

const FRI_FOLD_PO2: usize = 4;

pub const FRI_FOLD: usize = 1 << FRI_FOLD_PO2;

const FRI_MIN_DEGREE: usize = 256;

#[cfg(test)]
mod backend_parameter_tests {
    use risc0_core::field::{baby_bear::BabyBearExtElem, ExtElem};

    #[test]

    // Checks the backend proof parameters.
    fn backend_parameters_are_consistent() {
        assert_eq!(super::QUERIES, 50);
        assert_eq!(super::INV_RATE, 4);
        assert_eq!(super::FRI_FOLD, 16);
        assert_eq!(super::FRI_MIN_DEGREE, 256);
        assert_eq!(BabyBearExtElem::EXT_SIZE, 4);
    }
}
