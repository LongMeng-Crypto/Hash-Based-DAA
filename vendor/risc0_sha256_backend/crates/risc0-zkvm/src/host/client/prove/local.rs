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

use anyhow::Result;

use super::{Executor, Prover, ProverOpts};
use crate::{
    get_prover_server,
    host::server::{exec::executor::ExecutorImpl, session::NullSegmentRef},
    ExecutorEnv, ProveInfo, Receipt, SegmentInfo, SessionInfo, VerifierContext,
};

pub struct LocalProver {
    name: String,
}

impl LocalProver {

    // Creates the operation result.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
        }
    }
}

impl Prover for LocalProver {

    // Proves with ctx.
    fn prove_with_ctx(
        &self,
        env: ExecutorEnv<'_>,
        ctx: &VerifierContext,
        elf: &[u8],
        opts: &ProverOpts,
    ) -> Result<ProveInfo> {
        get_prover_server(opts)?.prove_with_ctx(env, ctx, elf)
    }

    // Returns name.
    fn get_name(&self) -> String {
        self.name.clone()
    }

    // Implements compress.
    fn compress(&self, opts: &ProverOpts, receipt: &Receipt) -> Result<Receipt> {
        get_prover_server(opts)?.compress(opts, receipt)
    }
}

impl Executor for LocalProver {

    // Implements execute.
    fn execute(&self, env: ExecutorEnv<'_>, elf: &[u8]) -> Result<SessionInfo> {
        let mut segments = Vec::new();
        let session = ExecutorImpl::from_elf(env, elf)
            .unwrap()
            .run_with_callback(|segment| {
                segments.push(SegmentInfo {
                    po2: segment.po2() as u32,
                    cycles: segment.user_cycles(),
                });
                Ok(Box::new(NullSegmentRef))
            })?;

        let receipt_claim = session.claim()?;
        Ok(SessionInfo {
            segments,
            journal: session.journal.unwrap_or_default(),
            exit_code: session.exit_code,
            receipt_claim: Some(receipt_claim),
        })
    }
}
