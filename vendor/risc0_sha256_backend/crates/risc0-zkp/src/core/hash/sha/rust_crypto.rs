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

//! [Rust Crypto] wrappers for the RISC0 Sha256 trait.
//!
//! [Rust Crypto]: https://github.com/RustCrypto
//!
//! # Usage
//!
//! ```rust
//! use risc0_zkp::core::hash::{
//!     sha::{cpu, rust_crypto::{Sha256, Digest as _}},
//! };
//!
//! // create a Sha256 object
//! let mut hasher = Sha256::<cpu::Impl>::new();
//!
//! // write input message
//! hasher.update(b"hello world");
//!
//! // read hash digest and consume hasher
//! let result = hasher.finalize();
//!
//! assert_eq!(hex::encode(result), "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
//!
//! // more concise version of the code above.
//! assert_eq!(hex::encode(Sha256::<cpu::Impl>::digest(b"hello world")),
//!     "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
//! );
//! ```

use alloc::{format, vec::Vec};
use core::fmt::{Debug, Formatter};

use digest::{
    block_buffer::Eager,
    const_oid::{AssociatedOid, ObjectIdentifier},
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper,
        CtVariableCoreWrapper, OutputSizeUser, TruncSide, UpdateCore, VariableOutputCore,
    },
    typenum::{U32, U64},
    HashMarker, InvalidOutputSize,
};
pub use digest::{Digest, Output};

use super::{BLOCK_BYTES, SHA256_INIT};

#[derive(Clone)]
pub struct Sha256VarCore<S: super::Sha256> {

    state: Option<S::DigestPtr>,

    block_len: u32,
}

impl<S: super::Sha256> HashMarker for Sha256VarCore<S> {}

impl<S: super::Sha256> BlockSizeUser for Sha256VarCore<S> {
    type BlockSize = U64;
}

impl<S: super::Sha256> BufferKindUser for Sha256VarCore<S> {
    type BufferKind = Eager;
}

impl<S: super::Sha256> UpdateCore for Sha256VarCore<S> {
    #[inline]

    // Implements update blocks.
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.block_len += u32::try_from(blocks.len()).unwrap();

        let current_state = self.state.as_deref().unwrap_or(&SHA256_INIT);
        self.state = Some(match unsafe { blocks.align_to::<super::Block>() } {
            (&[], aligned_blocks, &[]) => S::compress_slice(current_state, aligned_blocks),
            _ => S::compress_slice(
                current_state,
                &blocks
                    .iter()
                    .map(|block| bytemuck::pod_read_unaligned(block.as_slice()))
                    .collect::<Vec<_>>(),
            ),
        });
    }
}

impl<S: super::Sha256> OutputSizeUser for Sha256VarCore<S> {
    type OutputSize = U32;
}

impl<S: super::Sha256> VariableOutputCore for Sha256VarCore<S> {
    const TRUNC_SIDE: TruncSide = TruncSide::Left;

    #[inline]

    // Creates the operation result.
    fn new(output_size: usize) -> Result<Self, InvalidOutputSize> {
        let state = match output_size {
            32 => None,
            _ => return Err(InvalidOutputSize),
        };
        let block_len = 0;
        Ok(Self { state, block_len })
    }

    #[inline]

    // Implements finalize variable core.
    fn finalize_variable_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let bit_len =
            8 * (u32::try_from(buffer.get_pos()).unwrap() + (BLOCK_BYTES as u32) * self.block_len);
        buffer.len64_padding_be(bit_len as u64, |block| {

            let current_state = self.state.as_deref().unwrap_or(&SHA256_INIT);
            self.state = Some(
                match bytemuck::try_from_bytes::<super::Block>(block.as_slice()) {
                    Ok(b) => S::compress(current_state, b.as_half_blocks().0, b.as_half_blocks().1),
                    Err(_) => {
                        let b: super::Block = bytemuck::pod_read_unaligned(block.as_slice());
                        S::compress(current_state, b.as_half_blocks().0, b.as_half_blocks().1)
                    }
                },
            );
        });

        out.copy_from_slice(self.state.as_deref().unwrap().as_bytes())
    }
}

impl<S: super::Sha256> AlgorithmName for Sha256VarCore<S> {
    #[inline]

    // Writes alg name.
    fn write_alg_name(f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str("Sha256")
    }
}

impl<S: super::Sha256> Debug for Sha256VarCore<S> {
    #[inline]

    // Implements fmt.
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str(&format!(
            "Sha256VarCore<{}> {{ ... }}",
            core::any::type_name::<S>()
        ))
    }
}

#[doc(hidden)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct OidSha256;

impl AssociatedOid for OidSha256 {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
}

pub type Sha256<S> = CoreWrapper<CtVariableCoreWrapper<Sha256VarCore<S>, U32, OidSha256>>;
