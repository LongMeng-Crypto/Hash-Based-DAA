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

use crate::core::to_po2;

pub struct MerkleTreeParams {
    pub row_size: usize,
    pub col_size: usize,
    #[cfg(test)]
    pub queries: usize,
    #[cfg(feature = "prove")]
    pub layers: usize,
    #[cfg(test)]
    pub top_layer: usize,
    pub top_size: usize,
}

impl MerkleTreeParams {

    // Creates the operation result.
    pub fn new(row_size: usize, col_size: usize, queries: usize) -> Self {

        let layers: usize = to_po2(row_size);
        assert!(1 << layers == row_size);

        let mut top_layer = 0;
        for i in 1..layers {
            if (1 << i) > queries {
                break;
            }
            top_layer = i;
        }
        let top_size = 1 << top_layer;
        MerkleTreeParams {
            row_size,
            col_size,
            #[cfg(test)]
            queries,
            #[cfg(feature = "prove")]
            layers,
            #[cfg(test)]
            top_layer,
            top_size,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]

    // Creates merkle tree params 1.
    fn new_merkle_tree_params_1() {
        let row_size: usize = 1024;
        let col_size: usize = 1234;
        let queries: usize = 50;
        let params = MerkleTreeParams::new(row_size, col_size, queries);

        assert_eq!(params.row_size, row_size);
        assert_eq!(params.col_size, col_size);
        assert_eq!(params.queries, queries);
        assert_eq!(params.layers, 10);
        assert_eq!(params.top_layer, 5);
        assert_eq!(params.top_size, 32);
    }

    #[test]

    // Creates merkle tree params 2.
    fn new_merkle_tree_params_2() {
        let row_size: usize = 2048;
        let col_size: usize = 31337;
        let queries: usize = 128;
        let params = MerkleTreeParams::new(row_size, col_size, queries);

        assert_eq!(params.row_size, row_size);
        assert_eq!(params.col_size, col_size);
        assert_eq!(params.queries, queries);
        assert_eq!(params.layers, 11);
        assert_eq!(params.top_layer, 7);
        assert_eq!(params.top_size, 128);
    }
}
