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

extern crate alloc;

use alloc::vec::Vec;

use anyhow::Result;
use derive_more::Debug;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TraceEvent {

    InstructionStart {

        cycle: u64,

        #[debug("{pc:#010x}")]
        pc: u32,

        #[debug("{pc:#010x}")]
        insn: u32,
    },

    RegisterSet {

        idx: usize,

        #[debug("{value:#010x}")]
        value: u32,
    },

    MemorySet {

        #[debug("{addr:#010x}")]
        addr: u32,

        #[debug("{region:#04x?}")]
        region: Vec<u8>,
    },

    PageIn { cycles: u64 },

    PageOut { cycles: u64 },
}

pub trait TraceCallback {

    // Implements trace callback.
    fn trace_callback(&mut self, event: TraceEvent) -> Result<()>;
}

impl<F: FnMut(TraceEvent) -> Result<()>> TraceCallback for F {

    // Implements trace callback.
    fn trace_callback(&mut self, event: TraceEvent) -> Result<()> {
        self(event)
    }
}
