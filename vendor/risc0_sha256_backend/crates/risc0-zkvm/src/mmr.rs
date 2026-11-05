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

use crate::{claim::receipt::UnionClaim, sha::Digestible, Assumption};
use alloc::{boxed::Box, collections::VecDeque};
use anyhow::{bail, Result};
use risc0_circuit_recursion::control_id::ALLOWED_CONTROL_ROOT;

#[allow(dead_code)]
#[derive(Debug)]
pub struct MerkleMountainAccumulator<T: Peak> {
    peaks: VecDeque<T>,
}

#[allow(dead_code)]
impl<T> MerkleMountainAccumulator<T>
where
    T: Peak,
{

    // Creates the operation result.
    pub fn new() -> Self {
        Self {
            peaks: VecDeque::new(),
        }
    }

    // Implements insert.
    pub fn insert(&mut self, item: T::Item) -> Result<()> {
        let mut to_add: T = T::new(item);
        loop {
            if self.peaks.is_empty() {

                break;
            }
            if to_add.height() == self.peaks.back().unwrap().height() {
                let to_merge = self.peaks.pop_back().unwrap();
                to_add = *Peak::merge(to_add, to_merge)?;
            } else {
                break;
            }
        }
        self.peaks.push_back(to_add);
        Ok(())
    }

    // Implements root.
    pub fn root(mut self) -> Result<T::Item> {
        if self.is_empty() {
            bail!("no elements for host mmr");
        }
        if self.peaks.len() == 1 {
            return Ok(self.peaks.pop_back().unwrap().item());
        }

        let mut item = self.peaks.pop_front().unwrap().item();
        for peak in self.peaks.into_iter() {
            T::merge_item(&mut item, peak.item())?;
        }
        Ok(item)
    }

    // Checks empty.
    pub fn is_empty(&self) -> bool {
        self.peaks.is_empty()
    }
}

#[allow(dead_code)]
pub trait Peak {
    type Item;

    // Creates the operation result.
    fn new(item: Self::Item) -> Self;

    // Creates with height.
    fn new_with_height(item: Self::Item, height: u32) -> Self;

    // Implements height.
    fn height(&self) -> u32;

    // Implements item.
    fn item(self) -> Self::Item;

    // Implements merge.
    fn merge(a: Self, b: Self) -> Result<Box<Self>>
    where
        Self: Sized,
    {
        if a.height() != b.height() {
            bail!("merge attempted on peaks of different heights")
        }
        let height = a.height();
        let mut a: Self::Item = a.item();
        Self::merge_item(&mut a, b.item())?;
        Ok(Box::new(Self::new_with_height(a, height + 1)))
    }

    // Implements merge item.
    fn merge_item(a: &mut Self::Item, b: Self::Item) -> Result<()>;
}

#[derive(Debug)]
pub struct GuestPeak {
    digest: Assumption,
    height: u32,
}

impl Peak for GuestPeak {
    type Item = Assumption;

    // Creates the operation result.
    fn new(item: Self::Item) -> Self {
        Self::new_with_height(item, 0)
    }

    // Creates with height.
    fn new_with_height(item: Self::Item, height: u32) -> Self {
        Self {
            digest: item,
            height,
        }
    }

    // Implements height.
    fn height(&self) -> u32 {
        self.height
    }

    // Implements item.
    fn item(self) -> Self::Item {
        self.digest
    }

    // Implements merge item.
    fn merge_item(a: &mut Self::Item, b: Self::Item) -> Result<()> {
        let a_assumption = a.digest();
        let b_assumption = b.digest();

        let (left, right) = if a_assumption <= b_assumption {
            (a_assumption, b_assumption)
        } else {
            (b_assumption, a_assumption)
        };
        *a = Assumption {
            claim: UnionClaim { left, right }.digest(),
            control_root: ALLOWED_CONTROL_ROOT,
        };
        Ok(())
    }
}
