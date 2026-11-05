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

//! Claim types and utilities for the zkVM.

use borsh::{BorshDeserialize, BorshSerialize};
use risc0_binfmt::Digestible;
use risc0_zkp::core::digest::Digest;
use serde::{Deserialize, Serialize};

use crate::sha::Sha256;

pub(crate) mod maybe_pruned;
#[cfg(feature = "prove")]
pub(crate) mod merge;
pub(crate) mod receipt;
pub(crate) mod work;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub enum Unknown {}

impl Digestible for Unknown {

    // Implements digest.
    fn digest<S: Sha256>(&self) -> Digest {
        match *self {   }
    }
}

impl BorshSerialize for Unknown {

    // Serializes the operation result.
    fn serialize<W>(&self, _: &mut W) -> core::result::Result<(), borsh::io::Error> {
        match *self {   }
    }
}

impl BorshDeserialize for Unknown {

    // Deserializes reader.
    fn deserialize_reader<R>(_: &mut R) -> core::result::Result<Self, borsh::io::Error> {
        Err(borsh::io::Error::new(
            borsh::io::ErrorKind::InvalidData,
            "BorshDeserialize attempted to deserialize Unknown; data is malformed",
        ))
    }
}
