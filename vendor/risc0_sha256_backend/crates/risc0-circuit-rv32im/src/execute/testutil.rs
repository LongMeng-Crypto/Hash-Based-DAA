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

use std::collections::BTreeMap;

use anyhow::{bail, Result};
use risc0_binfmt::{MemoryImage, Program};
use risc0_core::scope;
use risc0_zkp::{
    core::{digest::Digest, log2_ceil},
    MAX_CYCLES_PO2,
};

use super::{
    executor::CycleLimit, pager::RESERVED_PAGING_CYCLES, platform::*, syscall::Syscall, Executor,
    SimpleSession, SyscallContext,
};

pub const DEFAULT_SESSION_LIMIT: CycleLimit = CycleLimit::Hard(1 << 24);
pub const MIN_CYCLES_PO2: usize = log2_ceil(RESERVED_CYCLES + RESERVED_PAGING_CYCLES as usize);

#[derive(Default)]
pub struct NullSyscall;

impl Syscall for NullSyscall {

    // Implements host read.
    fn host_read(&self, _ctx: &mut impl SyscallContext, _fd: u32, buf: &mut [u8]) -> Result<u32> {
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = i as u8;
        }
        Ok(buf.len() as u32)
    }

    // Implements host write.
    fn host_write(&self, _ctx: &mut impl SyscallContext, _fd: u32, _buf: &[u8]) -> Result<u32> {
        unimplemented!()
    }
}

// Implements execute.
pub fn execute<S: Syscall>(
    image: MemoryImage,
    segment_limit_po2: usize,
    max_insn_cycles: usize,
    max_cycles: CycleLimit,
    syscall_handler: &S,
    input_digest: Option<Digest>,
) -> Result<SimpleSession> {
    scope!("execute");

    if !(MIN_CYCLES_PO2..=MAX_CYCLES_PO2).contains(&segment_limit_po2) {
        bail!("Invalid segment_limit_po2: {segment_limit_po2}");
    }

    let mut segments = Vec::new();
    let trace = Vec::new();
    let result = Executor::new(image, syscall_handler, input_digest, trace, None).run(
        segment_limit_po2,
        max_insn_cycles,
        max_cycles,
        |segment| {
            tracing::trace!("{segment:#?}");
            segments.push(segment);
            Ok(())
        },
    )?;

    Ok(SimpleSession { segments, result })
}

pub mod user {
    use super::*;

    // Implements basic.
    pub fn basic() -> Program {
        let mut asm = Assembler::new();
        asm.li(REG_A1, 0x4000_0000);
        asm.ecall();
        asm.program()
    }

    // Implements simple loop.
    pub fn simple_loop(count: u32) -> Program {
        let mut asm = Assembler::new();
        asm.addi(REG_A4, REG_ZERO, 0);
        asm.li(REG_A5, count);

        asm.addi(REG_A4, REG_A4, 1);
        asm.blt(REG_A4, REG_A5, -4  );
        asm.lui(REG_A1, 0x1000);
        asm.ecall();
        asm.program()
    }
}

pub mod kernel {
    use super::*;

    // Implements basic.
    pub fn basic() -> Program {
        let mut asm = Assembler::new();
        asm.host_terminate(0, 0);
        asm.program()
    }

    // Implements simple loop.
    pub fn simple_loop(count: u32) -> Program {
        let mut asm = Assembler::new();
        asm.addi(REG_A4, REG_ZERO, 0);
        asm.li(REG_A5, count);

        asm.addi(REG_A4, REG_A4, 1);
        asm.blt(REG_A4, REG_A5, -4  );
        asm.host_terminate(0, 0);
        asm.program()
    }

    // Implements multi read.
    pub fn multi_read() -> Program {
        const LENGTHS: &[u32] = &[0, 1, 2, 3, 4, 5, 7, 13, 19, 40, 101];

        let ptr = 0x0050_0000;

        let mut asm = Assembler::new();
        asm.li(REG_T0, ptr);

        for i in 0..4 {

            for &len in LENGTHS {
                asm.host_ecall_read(0, ptr + i, len);
                for k in 0..len {
                    asm.lb(REG_T1, REG_T0, i + k);
                    asm.li(REG_T2, k);
                    asm.beq(REG_T1, REG_T2, 8);
                    asm.die();
                }
            }
        }

        asm.host_terminate(0, 0);

        asm.program()
    }
}

#[allow(unused)]
mod consts {
    pub(crate) const OP_BASE: u32 = 0b0110011;
    pub(crate) const OP_IMM: u32 = 0b0010011;
    pub(crate) const OP_LOAD: u32 = 0b0000011;
    pub(crate) const OP_STORE: u32 = 0b0100011;
    pub(crate) const OP_BRANCH: u32 = 0b1100011;
    pub(crate) const OP_JAL: u32 = 0b1101111;
    pub(crate) const OP_JALR: u32 = 0b1100111;
    pub(crate) const OP_LUI: u32 = 0b0110111;
    pub(crate) const OP_AUIPC: u32 = 0b0010111;
    pub(crate) const OP_ENV: u32 = 0b1110011;

    pub(crate) const FUNCT3_EQ: u32 = 0x0;
    pub(crate) const FUNCT3_NE: u32 = 0x1;
    pub(crate) const FUNCT3_LT: u32 = 0x4;
    pub(crate) const FUNCT3_GE: u32 = 0x5;
    pub(crate) const FUNCT3_LTU: u32 = 0x6;
    pub(crate) const FUNCT3_GEU: u32 = 0x7;

    pub(crate) const FUNCT3_BYTE: u32 = 0x0;
    pub(crate) const FUNCT3_HALF: u32 = 0x1;
    pub(crate) const FUNCT3_WORD: u32 = 0x2;
    pub(crate) const FUNCT3_BYTEU: u32 = 0x4;
    pub(crate) const FUNCT3_HALFU: u32 = 0x5;
}

use consts::*;

struct Assembler {
    text: Vec<u32>,
    data: BTreeMap<u32, u32>,
}

#[allow(dead_code)]
impl Assembler {

    // Creates the operation result.
    pub fn new() -> Self {
        Self {
            text: vec![],
            data: BTreeMap::new(),
        }
    }

    // Implements program.
    pub fn program(&self) -> Program {
        let entry = USER_START_ADDR + WORD_SIZE;
        let entry = entry.0;
        let mut pc = entry;

        let mut image: BTreeMap<_, _> = self
            .text
            .iter()
            .map(|instr| {
                let result = (pc, *instr);
                pc += WORD_SIZE as u32;
                result
            })
            .collect();

        image.extend(self.data.iter());

        Program::new_from_entry_and_image(entry, image)
    }

    // Implements word.
    pub fn word(&mut self, addr: u32, word: u32) {
        self.data.insert(addr, word);
    }

    // Adds the operation result.
    pub fn add(&mut self, rd: usize, rs1: usize, rs2: usize) {
        self.text.push(insn_r(
            0x00, rs2 as u32, rs1 as u32, 0x0, rd as u32, OP_BASE,
        ));
    }

    // Implements addi.
    pub fn addi(&mut self, rd: usize, rs1: usize, imm: u32) {
        self.text
            .push(insn_i(imm, rs1 as u32, 0x0, rd as u32, OP_IMM));
    }

    // Implements blt.
    pub fn blt(&mut self, rs1: usize, rs2: usize, offset: i32) {
        self.text.push(insn_b(
            offset as u32,
            rs2 as u32,
            rs1 as u32,
            FUNCT3_LT,
            OP_BRANCH,
        ));
    }

    // Implements beq.
    pub fn beq(&mut self, rs1: usize, rs2: usize, offset: i32) {
        self.text.push(insn_b(
            offset as u32,
            rs2 as u32,
            rs1 as u32,
            FUNCT3_EQ,
            OP_BRANCH,
        ));
    }

    // Implements bne.
    pub fn bne(&mut self, rs1: usize, rs2: usize, offset: i32) {
        self.text.push(insn_b(
            offset as u32,
            rs2 as u32,
            rs1 as u32,
            FUNCT3_NE,
            OP_BRANCH,
        ));
    }

    // Implements ecall.
    pub fn ecall(&mut self) {
        self.text.push(insn_i(0x0, 0x0, 0x0, 0x0, OP_ENV));
    }

    // Implements lui.
    pub fn lui(&mut self, rd: usize, imm: u32) {
        self.text.push(insn_u(imm, rd as u32, OP_LUI));
    }

    // Implements li.
    pub fn li(&mut self, rd: usize, imm: u32) {
        if imm < (1 << 11) {
            self.addi(rd, REG_ZERO, imm);
        } else {

            let low = ((imm as i32) << 20) >> 20;

            let high = (imm as i32 - low) >> 12;

            self.lui(rd, high as u32);
            self.addi(rd, rd, low as u32);
        }
    }

    // Implements lb.
    pub fn lb(&mut self, rd: usize, rs1: usize, imm: u32) {
        self.text
            .push(insn_i(imm, rs1 as u32, FUNCT3_BYTE, rd as u32, OP_LOAD));
    }

    // Implements lw.
    pub fn lw(&mut self, rd: usize, rs1: usize, imm: u32) {
        self.text
            .push(insn_i(imm, rs1 as u32, FUNCT3_WORD, rd as u32, OP_LOAD));
    }

    // Implements host ecall read.
    pub fn host_ecall_read(&mut self, fd: u32, ptr: u32, len: u32) {
        self.li(REG_A7, HOST_ECALL_READ);
        self.li(REG_A0, fd);
        self.li(REG_A1, ptr);
        self.li(REG_A2, len);
        self.ecall();
    }

    // Implements host terminate.
    pub fn host_terminate(&mut self, a0: u32, a1: u32) {
        self.li(REG_A7, HOST_ECALL_TERMINATE);
        self.li(REG_A0, a0);
        self.li(REG_A1, a1);
        self.ecall();
    }

    // Implements die.
    pub fn die(&mut self) {
        self.text.push(fence());
    }
}

// Implements insn r.
fn insn_r(funct7: u32, rs2: u32, rs1: u32, funct3: u32, rd: u32, opcode: u32) -> u32 {
    (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
}

// Implements insn i.
fn insn_i(imm: u32, rs1: u32, funct3: u32, rd: u32, opcode: u32) -> u32 {
    (imm << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
}

// Implements insn b.
fn insn_b(imm: u32, rs2: u32, rs1: u32, funct3: u32, opcode: u32) -> u32 {
    let imm_12 = (imm >> 12) & 0b1;
    let imm_10_5 = (imm >> 5) & 0b111111;
    let imm_11 = (imm >> 11) & 0b1;
    let imm_4_1 = (imm >> 1) & 0b1111;
    (((imm_12 << 6) | imm_10_5) << 25)
        | (rs2 << 20)
        | (rs1 << 15)
        | (funct3 << 12)
        | (((imm_4_1 << 1) | imm_11) << 7)
        | opcode
}

// Implements insn u.
fn insn_u(imm: u32, rd: u32, opcode: u32) -> u32 {
    (imm << 12) | (rd << 7) | opcode
}

// Implements fence.
fn fence() -> u32 {
    insn_i(0, 0, 0, 0, 0b0001111)
}
