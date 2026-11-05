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

use std::io::Read;

use anyhow::Result;

use risc0_binfmt::ByteAddr;

pub trait Syscall {

    // Implements host read.
    fn host_read(&self, ctx: &mut impl SyscallContext, fd: u32, buf: &mut [u8]) -> Result<u32>;

    // Implements host write.
    fn host_write(&self, ctx: &mut impl SyscallContext, fd: u32, buf: &[u8]) -> Result<u32>;
}

pub trait SyscallContext {

    // Implements peek register.
    fn peek_register(&mut self, idx: usize) -> Result<u32>;

    // Implements peek u32.
    fn peek_u32(&mut self, addr: ByteAddr) -> Result<u32>;

    // Implements peek u8.
    fn peek_u8(&mut self, addr: ByteAddr) -> Result<u8>;

    // Implements peek region.
    fn peek_region(&mut self, addr: ByteAddr, size: usize) -> Result<Vec<u8>>;

    // Reads region.
    fn read_region(&mut self, addr: ByteAddr, size: usize) -> Result<impl Read>;

    // Implements peek page.
    fn peek_page(&mut self, page_idx: u32) -> Result<Vec<u8>>;

    // Returns cycle.
    fn get_cycle(&self) -> u64;

    // Returns pc.
    fn get_pc(&self) -> u32;
}
